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
import config
import sqlite3
import re
import netaddr
import pprint
import db
from utils import *
import time
from abuseparsing import *
import traceback

import logging
logging.basicConfig(filename='debug.log',level=logging.DEBUG)

			
def addAddresses():
	
	ips  = []
	bads = 0
	for line in sys.stdin:
		for ip in extract_ips(line):
			ip = IP(ip)
			
			bad = not IsPublicIP(ip)

			if bad:
				if bads<15:
					sys.stderr.write("Bad IP: "+str(ip)+"\n")
				bads+=1
			else:
				ips.append(ip)

	print("IPs added "+str(db.addips(ips))+" Bad IPs: "+str(bads))


def continueProcessing():
	
	SPEEDUP_TWEAK=8
	
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
	
	retry=True
	while not whoiser.done() or len(queries_pending)>0 or retry:
		if retry:
			retry=False
		
		# Responses from worker threads
		resp = whoiser.response(timeout=0.01)
		if resp:
			resp_recv+=1
			
			query_legacy = False
			
			(req,reply,*rest) = resp
			
			ip = IP(req['ip'])
			legacy_reply = req.get('legacy')
			
			sys.stdout.write(legacy_reply and '^' or "-")
			sys.stdout.flush()
			
			# We have a response
			if reply==True:
				# Push again, try later, preferably much later, or by some other worker-proxy
					
				sys.stdout.write(">")
				sys.stdout.flush()
				
				time.sleep(5) # exhaust workers for a while. TODO: real rate limiting per proxy
				
				queries_pending.append(req)
				
			elif reply:
				quality = legacy_reply and 2 or 1
				(abuseemails,(startip,endip)) = legacy_reply and process_whois_abuse(reply) or process_rdap_abuse(reply)
				#print(legacy_reply and "LEGACY" or "RDAP",abuseemails,startip,endip)
				# one IP network is a possibility
				networkid = db.get_network(startip or ip, endip or ip, ip)
				db.add_network_abusemails(networkid,abuseemails,[quality]*len(abuseemails))
				db.ip_set_network(ip,networkid = networkid)

				if len(abuseemails)==0:
					query_legacy = True
					if legacy_reply:
						print("no emails found",req)
			
			# Worker failed (any reason)
			else:
				# We will try legacy query if rdap failed for any reason. 
				# Only legacy query error will be stored, even if rdap succeeded but found no emails
				query_legacy = True
				exc = rest[0]
				store_error = "".join(traceback.format_exception(None, exc, exc.__traceback__))
				print("failquery",ip,legacy_reply and "(LEGACY)" or "",FormatShortError(exc),len(rest)>1 and rest[1])
				
				db.ip_set_network(ip,failurereason=store_error)
			
				
			if query_legacy and not legacy_reply:
				
				sys.stdout.write("~")
				sys.stdout.flush()
				
				req['legacy'] = True
				# Add to queries again
				queries_pending.append(req)
			
			
			
			
		# Get more queries if they do not exist in pending
		if len(queries_pending)<SPEEDUP_TWEAK:
		
			row = unprocessed_ips.fetchone()
			if row:

				

				(ip,) = row
				ip = IP(ip)
				networkid = db.network_from_ip(ip)
				
				#TODO: Loop if we didn't query stuff
				if networkid and db.network_has_mails_processed(networkid):
					db.ip_set_network(ip,networkid)
					sys.stdout.write("'")
					sys.stdout.flush()
					req_unsent+=1
					retry = True
				else:
					queries_pending.append({"ip": ip })
				sys.stdout.write("_")
				sys.stdout.flush()
			else:
				if not exhaust_print:
					exhaust_print = True
					print("Exhausted queryable IPs")
		
		# Add queries from query queue
		try:
			request = queries_pending[0]
			if whoiser.request( request, timeout=0.01):
				queries_pending.pop(0)
				req_sent+=1
		except IndexError as e:
			pass
			
	print("Processing finished. Requests: {} Replies: {} instant, {} by whoiser".format(
									req_sent,	req_unsent,		resp_recv	))
def dumpFailed():
	for r in db.dump_all():
		(ip,networkid,failurereason,
			e1,e2,e3,q1,startip,endip,*rest) = r
		
		
		processed = networkid is not None
				
		ip = IP(ip)
		if ip.is_ipv4_mapped():
			ip = ip.ipv4()
		out = [ "\n\n\n", str(ip), "\n" ]
		

		if failurereason or networkid==-1:
			assert(failurereason)
			assert(networkid==-1)
			
			out += ["    ",failurereason.replace('\n', '\n    ')]
			
			print( "".join(out) )

			
def dumpAll(processedOnly=False):
	for r in db.dump_all():
		(ip,networkid,failurereason,
			e1,e2,e3,q1,startip,endip,*rest) = r
		
		
		processed = networkid is not None
				
		ip = IP(ip)
		if ip.is_ipv4_mapped():
			ip = ip.ipv4()
		out = [ str(ip) ]
		if not processedOnly or processed:
			
			if not processed:
				out += ["UNPROCESSED"]
			else:
				if failurereason or networkid==-1:
					assert(failurereason)
					assert(networkid==-1)
					out += ["FAIL"]
				else:
					if not q1:
						pass
					elif q1==1:
						out += ["RDAP"]
					elif q1==2:
						out += ["WHOIS"]
					else:
						out += ["???"]
				
				#out += emaillist
				if e1:
					out += [e1]
				if e2:
					out += [e2]
				if e3:
					out += [e3]
				if not e1 and not e2 and not e3:
					out += ["NOMAILS"]
					
			print( " ".join(out) )

			
cmd=len(sys.argv)>1 and sys.argv[1]
if cmd=="add":
	addAddresses()
elif cmd=="process":
	continueProcessing()
elif cmd=="dump":
	dumpAll()
elif cmd=="dump-failed":
	dumpFailed()
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