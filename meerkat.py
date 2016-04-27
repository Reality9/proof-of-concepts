#!/usr/bin/python
__author__ = 'rui@deniable.org'
import argparse
import re
import sys
 
# Standard DNS Request
#03/05/2014-14:39:17.164014 [**] Query TX 3a72 [**] yahoo.com [**] A [**] 10.128.23.149:44063 -> 10.126.26.100:53
dnsRequest = '(?P<date>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}).\d+\s+\[\*\*\]\sQuery\s+(?P<qtype>[^\s]+)\s+(?P<tag>[^\s]+)\s+\[\*\*\]\s(?P<domain>[^\s]+)\s\[\*\*\]\s(?P<qtype2>[^\s]+)\s\[\*\*\]\s(?P<srcip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):(?P<srcport>\d{1,5})\s->\s(?P<dstip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):(?P<dstport>\d{1,5})'
# Standard DNS Response
#03/05/2014-14:39:17.164014 [**] Response TX 3a72 [**] yahoo.com [**] A [**] TTL 1800 [**] 98.139.183.24 [**] 10.126.26.100:53 -> 10.128.23.149:44063
dnsResponse1 = '(?P<date>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}).\d+\s+\[\*\*\]\sResponse\s+(?P<qtype>[^\s]+)\s+(?P<tag>[^\s]+)\s+\[\*\*\]\s(?P<domain>[^\[]+)\s\[\*\*\]\s(?P<qtype2>[^\s]+)\s\[\*\*\]\sTTL\s(?P<ttl>\d+)\s\[\*\*\]\s(?P<response>[^\s]+)\s\[\*\*\]\s(?P<srcip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):(?P<srcport>\d{1,5})\s->\s(?P<dstip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):(?P<dstport>\d{1,5})'
 
# To be ingnored for now since they have no interest in the context of Passive DNS monitoring
# Standard DNS Response - No Such Name
#09/17/2013-20:07:58.576454 [**] Response TX f3bf [**] No Such Name [**] 8.8.8.8:53 -> 10.49.5.204:57628
# Standard DNS Response SOA: Multiple fields that specify which parts of the naming hiererchy a server implements
#09/17/2013-20:07:58.576454 [**] Response TX f3bf [**] <root> [**] SOA [**] TTL 1800 [**] a.root-servers.net [**] 8.8.8.8:53 -> 10.49.5.204:5762
# Others
#03/05/2014-14:39:17.164014 [**] Response TX 3a72 [**] Recursion Desired [**] 10.126.26.100:53 -> 10.128.23.149:44063
 
dict = {}
dict['dnsreq'] = dnsRequest
dict['dnsresp'] = dnsResponse1
 
def doMatch(line, dict_regexp):
        for item in dict_regexp:
                #print dict_regexp[item]
                matchObj = re.match(r'' + dict_regexp[item] + '', line, re.M|re.I)
                if args.nomatch:
                        if line and not line.isspace(): # checks if string not empty
                                print "No Match with \033[1m" + item + "\033[0m: " + line
                elif matchObj:
                        print "Rule matched: " + item
                        print "matchObj.group(): ", matchObj.group()
                        if args.debug:
                                print "Date: " + matchObj.group('date')
                                print "Query Type: " + matchObj.group('qtype')
                                print "Transaction ID: " + matchObj.group('tag')
                                print "Domain: " + matchObj.group('domain')
                                print "Query Type 2: " + matchObj.group('qtype2')
                                if item in "dnsresp":
                                        print "Response: " + matchObj.group('response')
                                print "Source IP: " + matchObj.group('srcip')
                                print "Source Port: " + matchObj.group('srcport')
                                print "Destination IP: " + matchObj.group('dstip')
                                print "Destination Port: " + matchObj.group('dstport')
                                print "matchObj.group(1) : ", matchObj.group(1)
                                print "matchObj.group(2) : ", matchObj.group(2)
                else:
                        pass
 
 
parser = argparse.ArgumentParser(description='\033[1m' + sys.argv[0] + '\033[0m searches  the  named input FILEs (or standard input if no files are named) for lines containing a match to the given PATTERN. PATTERNs are DNS queries and DNS replies from Suricata DNS logs.')
parser.add_argument('-f', '--file', help='Obtain  patterns  from  FILE,  one  per  line. (-f is specified by POSIX.)', required=False)
parser.add_argument('-s', '--stdinput', help='Read data from standard input. Like tail -f logfile | python -u ' + sys.argv[0] + '. (Do not mess with EOF, so use Python unbuffered mode. I mean do not forget python -u)', action='store_true', required=False)
parser.add_argument('-v', '--nomatch', help='Invert the sense of matching, to select non-matching lines. (-v is specified by POSIX.)', action='store_true', required=False)
parser.add_argument('-e', '--examples', help='Some Use Case scenarios for slackers!', action='store_true', required=False)
parser.add_argument('-d', '--debug', help='Enables debugging.', action='store_true', required=False)
 
args = parser.parse_args()
 
if args.file:
        for line in open(args.file):
                doMatch(line, dict)
elif args.stdinput:
        while 1:
                line = sys.stdin.readline()
                doMatch(line, dict)
                if not line: break
elif args.examples:
        print "Lazy mode on! Here are some usage cases:"
        print "$ cat /var/log/suricata/dns.log | python -u meerkat.py -s -d"
        print "$ python meerkat.py -f suricata.log"
        print "$ tail -f /var/log/suricata/dns.log | python -u meerkat.py -s"
else:
        print "Something went wrong! Read the source Luke! Or just use -h for help!"
