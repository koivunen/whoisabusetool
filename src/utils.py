from multiprocessing import Pool, TimeoutError
import fileinput
import csv
import sys
import sqlite3
import re
import netaddr
import pprint
import db

printp = pprint.PrettyPrinter(indent=4)

class safelist(list):
    def get(self, index, default=None):
        try:
            return self.__getitem__(index)
        except IndexError:
            return default

			
def extract_ips(data):
    return re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", data)

	
	
	
	
	
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
