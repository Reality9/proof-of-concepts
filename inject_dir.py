import os
import sys
from scapy.all import rdpcap, sendp

def usage():
	print """
SYNOPSIS
python inject_pcap_dir.py -d <path/to/dir> 
"""

def main(*args):
	if len(sys.argv) != 2:
		usage()
		sys.exit(0)
	else:
		directory = sys.argv[1]
		caps = os.listdir(directory)
		for pcapfile in caps:
			try:
				#sendp(pcapfile, iface='eth0', loop=0, verbose=0)
				sendp(rdpcap('%s/%s' % (directory, pcapfile)), verbose=0)
				print "PCAP injected: %s" % pcapfile
			except:
				pass

if __name__ == "__main__":
	sys.exit(main(*sys.argv))
