#!/usr/bin/en python2

import sys
import binascii
import threading
from layerscapy.HomePlugAV import *
from optparse import OptionParser

"""
    Copyright (C) NMK setter for local device without DAK tool by julioxus and aespinosa
"""

dictio = {}

def appendindic(pkt):
    macad = pkt.src
    if macad not in dictio.keys() and macad != "00:00:00:00:00:00":
        dictio[macad] = None
        print "\t Found Station: %s" % macad

def listen():
    sniff(prn=appendindic, lfilter=lambda pkt:pkt.haslayer(HomePlugAV), timeout=5)

if __name__ == "__main__":
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option("-i", "--iface", dest="iface", default="eth0",
        help="select an interface to Enable sniff mode and sniff indicates packets", metavar="INTERFACE")
    parser.add_option("-s", "--source", dest="sourcemac", default="00:c4:ff:ee:00:00",
        help="source MAC address to use", metavar="SOURCEMAC")
    parser.add_option("-l", "--localdevice", dest="localdevice",
        help="MAC address of your local attached PLC", metavar="LOCALDEVICE")
    parser.add_option("-k", "--key", dest="nmk", default="\x00"*16,
        help="NMK key to configure", metavar="NMK")



    (options, args) = parser.parse_args()
    if not options.localdevice:   # if localdevice is not given
        parser.error('Attacker MAC address not given')

    # Set NMK to attacker device
    zeroDAK = "\x00"*16
    pkt = Ether(dst=options.localdevice)/HomePlugAV()/SetEncryptionKeyRequest(NMK=options.nmk, EKS=1, DAK=options.nmk, DestinationMAC=options.localdevice,PayloadEncKeySelect=0x0f)
    ans = srp1(pkt, iface=options.iface,verbose=False,timeout=5)
    if ans is None:
        print "Packet sent with no answer..."
        exit(1)
    if ans[1].haslayer(SetEncryptionKeyConfirmation):
        print "Set NMK key with success!"
    else:
        print "There was an error while setting the NMK. Is the localdevice wired to your computer?"

