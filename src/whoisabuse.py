#!/usr/bin/python3

"""

 - aggregate IPs to Class C?
 - Any usable libraries?
	- https://github.com/secynic/ipwhois
 - go through multiple services to not be rate limited too hard?

"""

import fileinput
import csv
import sys
import sqlite3
import re
import netaddr
import pprint
pp = pprint.PrettyPrinter(indent=4)
def printp(v):
	print(pp.pprint(v))
class safelist(list):
    def get(self, index, default=None):
        try:
            return self.__getitem__(index)
        except IndexError:
            return default
			
conn = sqlite3.connect('state.db',detect_types=sqlite3.PARSE_DECLTYPES)

cur = conn.cursor()

cur.execute('''
	CREATE TABLE IF NOT EXISTS mapping (
	 ip  		integer(32) not null primary key, 
	 cidr 		integer(6) not null default 32, 
	 e1  		string, 
	 e2  		string, 
	 e3  		string,
	 UNIQUE(ip,cidr)
)''')


from ipwhois import IPWhois

def extract_ips(data):
    return re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", data)
	
	
def addAddresses():
	
	ips = {}
	#for line in fileinput.input():
	for line in sys.stdin:
		for ip in extract_ips(line):
			ip = int(netaddr.IPAddress(ip))
			#TODO: Truncate?
			ips[ip] = True
		
	iplist=[]
	for ip in ips:
		print("adding: ",str(netaddr.IPAddress(ip)))
		cur.execute('INSERT INTO mapping(ip) values ('+str(ip)+')')
	
cur2 = conn.cursor()
def continueProcessing():
	for row in cur.execute('SELECT * FROM mapping where e1 IS NULL'):
		ip = netaddr.IPAddress(row[0])
		print("Processing",str(ip))
		whois = IPWhois(str(ip))
		r = whois.lookup_rdap()
		
		abuseemails=safelist()
		
		net = r.get('network')
		netaddrs = net and netaddr.IPNetwork(net.get("cidr"))
		cidr = netaddrs.prefixlen or 32
		start_address = netaddrs.first
		end_address = netaddrs.last

		for name,data in r.get('objects').items():
			print("- "+str(name))
			contact = data.get('contact')
			if not contact:
				print("\tno contact")
				continue
			roles = data.get('roles')
			if not roles or (not 'Abuse' in roles and not 'abuse' in roles):
				print("\tNot abuse role")
				continue
			email = contact.get('email')
			if not email:
				print("\tnot email")
				continue
			abuseemails.append(isinstance(email, str) and email or email[0].get('value'))
			
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
	for row in cur.execute('SELECT * FROM mapping'):
		#print(">",str(netaddr.IPAddress(row[0]))+"/"+str(row[1]),row[2]==None and "unprocessed" or "",row[3] or "",row[4] or "")
		if not processedOnly or row[2] is not None:
			print(str(netaddr.IPAddress(row[0]))+" "+(row[2]==None and "unprocessed" or row[2] or "")+" "+(row[3] or ""),row[4] or "")
	
	
cmd=sys.argv[1]
if cmd=="add":
	addAddresses()
elif cmd=="process":
	continueProcessing()
elif cmd=="dump":
	dumpAll()
elif cmd=="dump-processed":
	dumpAll(True)
else:
	print("""Usage:
		add
		process
		dump
		dump-processed""")
		
conn.commit()