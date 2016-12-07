import csv
import sys
import re
import netaddr
import pprint
from utils import *
import time

iprange_search = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \- (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

	
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
				res = iprange_search.search(range)
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
		res = iprange_search.search(raw) #TODO: Findall
		res = res and res.groups()
		if res:
			(start_address,end_address) = res
			start_address, end_address  = netaddr.IPAddress(start_address), netaddr.IPAddress(end_address)

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

#TODO: Clamper instead of rejecter?
def _sane_whois_netrange(a,b=None):
	if b is None:
		b=a
	if not a:
		return False
	a = int(netaddr.IPAddress(a))
	b = int(netaddr.IPAddress(b))
	if int(a)>int(b):
		return False
	
	if a != b:
		range = 32-math.floor(math.log2(b-a))
		if range<8:
			return False
			
	return True
	
def process_rdap_abuse(r):

	abuseemails={}
	
	net = r.get('network')
	
	start_address = net.get('start_address')
	end_address = net.get('end_address')
	if start_address:
		start_address = netaddr.IPAddress(start_address)
		end_address = netaddr.IPAddress(end_address)
	if not _sane_whois_netrange(start_address):
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

