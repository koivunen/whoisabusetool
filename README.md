# whoisabusetool
Processes list of IPs and tries to figure out abuse email(s) for them. 

Done as part of a research project for the [Department of Information Technology](http://www.utu.fi/en/units/sci/units/it/Pages/home.aspx) of [University of Turku](http://utu.fi)


Work In Progress, but has been tested with 10000+ IPs and 3 proxies.



### Usage

 - Install dependencies below
 - Set up proxy servers and add them to config.py
 - See below

```
$ python3 whoisabuse.py
Usage:
        add             Add IPs from stdin
        process         Start processing IPs
        process-failed  Mark failed IPs to be reprocessed
        dump            Dump IPs with any results
        dump-processed  Dump IPs that have email results

```



### Example 

```
$ echo 192.30.253.113 | python whoisabuse.py add
IPs added (1, 1) Bad IPs: 0

$ python whoisabuse.py process
Processing 192.30.253.113
Exhausted queryable IPs
Processing finished. Requests: 1 Replies: 0 instant, 1 by whoiser

$ python whoisabuse.py dump
192.30.253.113 hostmaster@github.com

```

### Dependencies

```bash
pip install --upgrade ipwhois
pip install netaddr
```

You also need 3+ proxies to efficiently query the databases.


### TODO

 - Add timestamps!
 - Optimize CPU usage and database queries
 - Normalize email database
 - Allow choosing maximum network size
 - Improve error logging
 - Improve proxying system

### Bugs

 - Possibly many, work in progress
 
