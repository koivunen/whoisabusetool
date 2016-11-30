# whoisabusetool
Processes list of IPs and tries to figure out abuse email(s) for them

Done as part of a research project for [University of Turku](http://utu.fi)

Work In Progress

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
```
pip install --upgrade ipwhois
pip install netaddr
```
