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
			bad = ip.is_multicast() or ip.is_private() or ip.is_reserved() or ip.is_loopback() or int(ip)<2
			
			if bad:
				if bads<3:
					sys.stderr.write("Bad IP: "+str(ip)+"\n")
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
			range = net and net.get('range')
			netaddrs = net and net.get("cidr")
			
			if range:
				res = re.match(r".*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \- (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",range)
				res = res and res.groups()
				if res:
					(start_address,end_address) = res
					if end_address:
						start_address, end_address = netaddr.IPAddress(start_address), netaddr.IPAddress(end_address)

			if not start_address and netaddrs:
				netaddrs =  netaddr.IPNetwork(netaddrs)
				start_address 	= netaddrs and netaddrs.first
				end_address 	= netaddrs and netaddrs.last
			if not start_address:
				assert(False) #TODO: Handle "range" 
				
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


def continueProcessing():
	whoiser.start()
	unprocessed_ips = db.get_unprocessed(random_order = True)
	queries_pending=[]
	
	# Status stuff
	req_sent = 0
	req_unsent = 0
	resp_recv = 0
	req_legacy = 0
	exhaust_print=False
	
	first=True
	while not whoiser.done() or len(queries_pending)>0 or first:
		if first:
			first=False
		
		resp = whoiser.response(timeout=0.01)
		if resp:
			resp_recv+=1
			no_emails = False
			(req,returned,*rest) = resp
			ip = netaddr.IPAddress(req['ip'])
			
			if returned:
				if req.get('legacy'):
					(abuseemails,(startip,endip)) = process_whois_abuse(returned)
				else:
					(abuseemails,(startip,endip)) = process_rdap_abuse(returned)
				if len(abuseemails)>0:
					#print("got emails for",ip,abuseemails)
					if startip:
						networkid = db.get_network(startip, endip)
					else:
						networkid = db.get_network(ip,ip)
					
					db.add_network_abusemails(networkid,abuseemails)
					db.ip_set_network(ip,networkid)
					
				else:
					print("no emails found",req)
					no_emails = True
				
			else:
				no_emails = True
				print("failquery",ip,rest)
				db.ip_set_network(ip,-1)
				
			if no_emails and not req.get('legacy'):
				print("LEGACY QUERYING",ip)
				req['legacy'] = True
				# Add to queries again
				queries_pending.append(req)

		# Get more queries if they do not exist in pending
		if len(queries_pending)<1:
			row = unprocessed_ips.fetchone()
			if row:
				(ip,) = row
				ip = netaddr.IPAddress(ip)
				networkid = db.network_from_ip(ip)
				req_sent+=1
				if networkid:
					print("already found result",ip)
					db.ip_set_network(ip,networkid)
					req_unsent+=1
				else:
					queries_pending.append({"ip": ip })
				sys.stdout.write(":")
				sys.stdout.flush()
			else:
				if not exhaust_print:
					exhaust_print = True
					print("Exhausted queryable IPs")
				
		try:
			request = queries_pending[0]
			if whoiser.request( request, timeout=0.01):
				queries_pending.pop(0)
		except IndexError as e:
			pass
			
	print("Processing finished. Requests: {} Replies: {} instant, {} by whoiser".format(
									req_sent,	req_unsent,		resp_recv	))
	
def dumpAll(processedOnly=False):
	for r in db.dump_all():
		(ip,e1,e2,e3) = r
		if not processedOnly or e1 is not None:
			extra = e1 or "Unprocessed"
			print( "%s%s" % ( str(netaddr.IPAddress(ip)), extra and (" %s")%(extra) or "" ) )

			
cmd=len(sys.argv)>1 and sys.argv[1]
if cmd=="add":
	addAddresses()
elif cmd=="process":
	continueProcessing()
elif cmd=="dump":
	dumpAll()
elif cmd=="process-failed":
	db.clear_failed_ips()
	continueProcessing()
elif cmd=="dump-processed":
	dumpAll(True)
else:
	print(
"""Usage:
	add				Add IPs from stdin
	process			Start processing IPs
	process-failed	Mark failed IPs to be reprocessed
	dump			Dump IPs with any results
	dump-processed	Dump IPs that have email results
""")
		
db.commit()