#!/usr/bin/python3

"""

 - aggregate IPs to Class C?
 - Any usable libraries?
	- https://github.com/secynic/ipwhois
 - go through multiple services to not be rate limited too hard?

"""

from multiprocessing import Pool, TimeoutError
import fileinput
import csv
import sys
import sqlite3
import re
import netaddr
import pprint
import db
import whoiser
from utils import *
import time



def addAddresses():
	
	ips  = []
	bads = 0
	for line in sys.stdin:
		for ip in extract_ips(line):
			ip = netaddr.IPAddress(ip)
			bad = ip.is_multicast() or ip.is_private() or ip.is_loopback()
			
			if bad:
				if bads<2:
					print("Bad IP: ",ip)
				bads+=1
			else:
				ips.append(ip)

	print("IPs added "+str(db.addips(ips))+" Bad IPs: "+str(bads))


	
def _find_rdap_emails(r,abuseemails,abuse_only=False):
	for name,data in r.get('objects').items():
	
		contact = data.get('contact')
		
		if not contact:
			continue
			
		roles = data.get('roles')
		if abuse_only:
			if not roles or (not 'Abuse' in roles and not 'abuse' in roles):
				continue
			
		email = contact.get('email')
		if email:
			email = isinstance(email, str) and email or email[0].get('value')
			abuseemails[email] = True
			continue
			

def process_whois_abuse(r):

	abuseemails={}
	
	start_address,end_address = False,False
	
	nets = r.get('nets')
	if nets and len(nets)>0:
		for net in nets:
			emails = net.get('emails') or (net.get('email') and [net.get('email')])

			if not emails or len(emails)==0:
				continue
				
			netaddrs = net and net.get("cidr") and netaddr.IPNetwork(net.get("cidr"))
			if netaddrs:
				start_address 	= netaddrs and netaddrs.first
				end_address 	= netaddrs and netaddrs.last
			if not start_address:
				assert(not net.get('range')) #TODO: Handle "range" 
				
			for email in emails:
				abuseemails[email] = True
		
	retlist = []
	for email in abuseemails:
		retlist.append(email)

	# raw process find if nothing found
	raw = r.get('raw')
	if not start_address:
		res = re.match(r".*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \- (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",raw)
		res = res and res.groups()
		if res:
			(start_address,end_address) = res
			start_address, end_address  = 	netaddr.IPAddress(start_address), netaddr.IPAddress(end_address)

	if len(retlist)==0 and raw:
		t = raw.lower().splitlines()
		for i,line in enumerate(t):
			if line.find("abuse")>-1:
				for e in get_emails(line):
					retlist.append(e)
				if len(retlist)==0:
					emails = len(t)==i+1 and [] or get_emails(t[i+1])
					for e in emails:
						retlist.append(e)
					
	return (retlist,(start_address,end_address))
	


def process_rdap_abuse(r):

	abuseemails={}
	
	net = r.get('network')
	
	start_address = net.get('start_address')
	end_address = net.get('end_address')
	if start_address:
		start_address = netaddr.IPAddress(start_address)
		end_address = netaddr.IPAddress(end_address)
	if not start_address:
		netaddrs = net and net.get("cidr") and netaddr.IPNetwork(net.get("cidr"))
		start_address 	= netaddrs and netaddrs.first
		end_address 	= netaddrs and netaddrs.last
	if not start_address:
		print("Response with no addressing??")
		
	_find_rdap_emails(r,abuseemails,True)
	if len(abuseemails)==0:
		_find_rdap_emails(r,abuseemails,False)
	
	retlist = []
	
	for email in abuseemails:
		retlist.append(email)
	
	return (retlist,(start_address,end_address))


if False:
	whoiser.start()
	print(
		#whoiser.request({"ip":"127.0.0.1"}),
		whoiser.request({"ip":"130.232.4.4"}),
		whoiser.request({"ip":"130.200.4.4"}),
		whoiser.request({"ip":"130.232.1.1"})
		)
	while not whoiser.done():
		time.sleep(0.1)
		resp = whoiser.response(timeout=0.01)
		if resp:
			#print("RESPONSE",resp)
			no_emails = False
			(req,returned,*rest) = resp
			if returned:
				if req.get('legacy'):
					(emails,*a) = process_whois_abuse(returned)
				else:
					(emails,*a) = process_rdap_abuse(returned)
				
				if len(emails)>0:
					print("got emails for",req,emails,a)
				else:
					print("no emails found",req)
					no_emails = True
				
			else:
				no_emails = True
				print("failquery",req['ip'],rest)
				
			if (True or no_emails) and not req.get('legacy'):
				print("LEGACY QUERY FOR",req['ip'])
				req['legacy'] = True
				whoiser.request(req)
				
def continueProcessing():
	whoiser.start()
	unprocessed = db.get_unprocessed()
	row = unprocessed.fetchone()
	have_more = row and True
	while not whoiser.done() or have_more or row:
		row = row or (have_more and unprocessed.fetchone())
		
		if row is None:
			have_more = False
		else:
			
			ip = int(netaddr.IPAddress(row['ip']))
			
			request = { "ip": ip }
			if whoiser.request( request, timeout=0.01):
				sys.stdout.write(".")
				sys.stdout.flush(".")
				row = False
				
		resp = whoiser.response(timeout=0.01)
		if resp:
		
			(requested,response,*other) = resp
			ip = requested['ip']
			if response==False:
				print("Setting failure",ip,db.ip_setfail(ip))
				pass
			else:
				(ip, abuseemails, startip, endip ) = resp
				networkids = db.add_network(startip, endip)
				db.add_network_abusemails(networkid,abuseemails)
				cur2.execute("UPDATE mapping set e1=?,e2=?,e3=?,cidr=? where ip BETWEEN ? and ?",
							(
								abuseemails.get(0,""),
								abuseemails.get(1,None),
								abuseemails.get(2,None),
								cidr,
								int(start_address),
								int(end_address)
							)
						)

def dumpAll(processedOnly=False):
	for r in db.dump_all():
		e1 = r['e1']
		if not processedOnly or e1 is not None:
			extra = e1 or "Unprocessed"
			print( "%s%s" % ( str(netaddr.IPAddress(r['ip'])), extra and (" %s")%(extra) or "" ) )

			
cmd=len(sys.argv)>1 and sys.argv[1]
if cmd=="add":
	addAddresses()
elif cmd=="process":
	continueProcessing()
elif cmd=="dump":
	dumpAll()
elif cmd=="dump-processed":
	dumpAll(True)
else:
	print(
"""Usage:
	add
	process
	dump
	dump-processed""")
		
db.commit()