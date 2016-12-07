# From https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8


# Constructed with help from
# http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
# Try it on regex101: https://regex101.com/r/yVdrJQ/1

import re

IPV4SEG  = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
IPV6SEG  = r'(?:(?:[0-9a-fA-F]){1,4})'
IPV6GROUPS = (
    r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
    r'(?:' + IPV6SEG + r':){1,7}:',                           # 1::                                 1:2:3:4:5:6:7::
    r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,                 # 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
    r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',  # 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
    r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',  # 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
    r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',  # 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
    r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
    IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',             # 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
    r':(?:(?::' + IPV6SEG + r'){1,7}|:)',                     # ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
    r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',       # fe80::7:8%eth0     fe80::7:8%1  (link-local IPv6 addresses with zone index)
    r'::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,     # ::255.255.255.255  ::ffff:255.255.255.255  ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r'(?:' + IPV6SEG + r':){1,4}:[^\s:]' + IPV4ADDR,          # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
)
IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])  # Reverse rows for greedy match


tests = [
    '1::',
    '1:2:3:4:5:6:7::',
    '1::8',
    '1:2:3:4:5:6::8',
    '1:2:3:4:5:6::8',
    '1::7:8',
    '1:2:3:4:5::7:8',
    '1:2:3:4:5::8',
    '1::6:7:8',
    '1:2:3:4::6:7:8',
    '1:2:3:4::8',
    '1::5:6:7:8',
    '1:2:3::5:6:7:8',
    '1:2:3::8',
    '1::4:5:6:7:8',
    '1:2::4:5:6:7:8',
    '1:2::8',
    '1::3:4:5:6:7:8',
    '1::3:4:5:6:7:8',
    '1::8',
    '::2:3:4:5:6:7:8',
    '::2:3:4:5:6:7:8',
    '::8',
    '::',
    'fe80::7:8%eth0',
    'fe80::7:8%1',
    '::255.255.255.255',
    '::ffff:255.255.255.255',
    '::ffff:0:255.255.255.255',
    '2001:db8:3:4::192.0.2.33',
    '64:ff9b::192.0.2.33',
]

# IPV6ADDR Tests
def test_individual(tests):
    for t in tests:
        assert re.search(IPV6ADDR, t).group() == t

# MULTILINE
def test_multiline(tests):
    _tests = tests[:]
    for t in re.findall(IPV6ADDR, ' '.join(tests)):
        _tests.remove(t)
    assert not _tests

test_individual(tests)
test_multiline(tests)
