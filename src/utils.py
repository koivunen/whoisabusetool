from multiprocessing import Pool, TimeoutError
import fileinput
import sys
import sqlite3
import re
import netaddr
import pprint
import traceback

def IP(var):
	if isinstance(var,str):
		return netaddr.IPAddress(var).ipv6()
	elif isinstance(var,int):
		return netaddr.IPAddress(var,version=6)
	return netaddr.IPAddress(var)

def FormatShortError(exc):
	return "".join(traceback.format_exception(None, exc, exc.__traceback__,chain=True))
		
def IsPublicIP(ip):
	bad = False
	
	if ip.is_ipv4_mapped():
		ip4 = ip.ipv4()
		
		bad = ip4.is_multicast() or   \
				ip4.is_private()   or \
				ip4.is_reserved()  or \
				ip4.is_loopback()  or \
				ip4.is_hostmask()  or \
				ip4.is_netmask() or not ip.is_unicast()
	else:
		bad = ip.is_multicast() or   \
			ip.is_private()   or \
			ip.is_reserved()  or \
			ip.is_loopback()  or \
			ip.is_hostmask()  or \
			ip.is_netmask() or not ip.is_unicast()
	return not bad
		
printp = pprint.PrettyPrinter(indent=4)

class safelist(list):
    def get(self, index, default=None):
        try:
            return self.__getitem__(index)
        except IndexError:
            return default

# http://stackoverflow.com/a/17871737

from ipv6re import IPV6ADDR as ipv6_regex
ipv6_regex = re.compile(ipv6_regex)

def extract_ips(data):
	a = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", data)
	b = ipv6_regex.findall(data)
	return a+b
	
	
###################################
## Modified from https://gist.github.com/dideler/5219706
###################################

import os.path
import re
import lepl.apps.rfc3696

email_validator = lepl.apps.rfc3696.Email()
emailfindregex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                    "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                    "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))

def get_emails(s):
    """Returns an iterator of matched emails found in string s."""
    # Removing lines that start with '//' because the regular expression
    # mistakenly matches patterns like 'http://foo@bar.com' as '//foo@bar.com'.
    return (email[0] for email in re.findall(emailfindregex, s) if email_validator(email[0]))
