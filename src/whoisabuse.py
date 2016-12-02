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
from utils import *
import time
from abuseparsing import *
import traceback

def addAddresses():
	
	ips  = []
	bads = 0
	for line in sys.stdin:
		for ip in extract_ips(line):
			ip = netaddr.IPAddress(ip)
			bad = ip.is_multicast() or   \
					ip.is_private()   or \
					ip.is_reserved()  or \
					ip.is_loopback()  or \
					ip.is_hostmask()  or \
					ip.is_netmask()
					
			if bad:
				if bads<15:
					sys.stderr.write("Bad IP: "+str(ip)+"\n")
				bads+=1
			else:
				ips.append(ip)

	print("IPs added "+str(db.addips(ips))+" Bad IPs: "+str(bads))


def continueProcessing():
	
	import whoiser
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
		
		# Responses from worker threads
		resp = whoiser.response(timeout=0.01)
		if resp:
			resp_recv+=1
			
			sys.stdout.write("-")
			sys.stdout.flush()
			
			query_legacy = False
			
			(req,reply,*rest) = resp
			
			ip = netaddr.IPAddress(req['ip'])
			legacy_reply = req.get('legacy')
			
			# We have a response
			if reply:
			
				quality = legacy_reply and 2 or 1
				(abuseemails,(startip,endip)) = legacy_reply and process_whois_abuse(reply) or process_rdap_abuse(reply)
				# one IP network is a possibility
				networkid = db.get_network(startip or ip, endip or ip, ip)
				db.add_network_abusemails(networkid,abuseemails,[quality]*len(abuseemails))
				db.ip_set_network(ip,networkid = networkid)

				if len(abuseemails)==0:
					query_legacy = True
					print("no emails found",req)
			
			# Worker failed (any reason)
			else:
				# We will try legacy query if rdap failed for any reason. 
				# Only legacy query error will be stored, even if rdap succeeded but found no emails
				query_legacy = True
				exc = rest[0]
				store_error = "".join(traceback.format_exception(None, exc, exc.__traceback__))
				print("failquery",ip,legacy_reply and "(LEGACY)" or "",exc)
				
				db.ip_set_network(ip,failurereason=store_error)
			
				
			if query_legacy and not legacy_reply:
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
				
				#TODO: Loop if we didn't query stuff
				if networkid and db.network_has_mails_processed(networkid):
					db.ip_set_network(ip,networkid)
					req_unsent+=1
				else:
					queries_pending.append({"ip": ip })
				sys.stdout.write("_")
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