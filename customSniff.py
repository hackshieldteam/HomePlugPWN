#!/usr/bin/en python2

from scapy.all import *
from layerscapy.HomePlugAV import *
from optparse import OptionParser

def processPkt(pkt):
    print(pkt.summary())
    if pkt.haslayer(SetEncryptionKeyRequest):
        pkt.show()

if __name__ == "__main__":
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option("-i", "--iface", dest="iface", default="eth0",
        help="select an interface to Enable sniff mode and sniff indicates packets", metavar="INTERFACE")
    parser.add_option("-s", "--source", dest="sourcemac", default="00:c4:ff:ee:00:00",
        help="source MAC address to use", metavar="SOURCEMAC")
    (options, args) = parser.parse_args()
    '''
    print "[+] Enabling sniff mode"
    pkt = Ether(src=options.sourcemac)/HomePlugAV()/SnifferRequest(SnifferControl=1) # We enable Sniff mode here
    sendp(pkt, iface=options.iface, verbose=False)
    print "[+] Listening for CCo station..."
    sniff(prn=appendindic, lfilter=lambda pkt:pkt.haslayer(HomePlugAV)) 
    '''
    sniff(prn=processPkt, lfilter=lambda pkt: pkt.haslayer(HomePlugAV), iface=options.iface)
