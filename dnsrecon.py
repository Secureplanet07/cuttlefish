"""
Adapted from 
"""

#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: dnsrecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]
HOSTNAME = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address)# grab the hostname         
host = subprocess.check_output(HOSTNAME, shell=True).strip()
print "INFO: Attempting Domain Transfer on " + host
ZT = "dig @%s.thinc.local thinc.local axfr" % (host)
ztresults = subprocess.check_output(ZT, shell=True)
print "[*] results:\n\t{}".format(ztresults)