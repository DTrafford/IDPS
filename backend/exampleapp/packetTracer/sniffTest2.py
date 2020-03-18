import sys, os
import logging

from scapy.all import *
from datetime import datetime
import urllib.request
import requests
import json
import RuleFileReader
from collections import OrderedDict
from packet import Packet
from Rule import Rule
import time
from datetime import datetime
from scapy.layers.inet import UDP

pckNum = 0
packet_list = OrderedDict()
apikey = '79aa5e1eed184359a87119a5a9dace18'

class ids:
    __flagsTCP = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
    }

    __ip_cnt_TCP = {}  # ip address requests counter

    __THRESH = 1000

    now = datetime.now()
    current_file = 'captured_pkts' + str(now) + '.pcap'

    ruleList = []

    import pathlib
    basepath = 'X:/CyberSecurity/CBER710-Capsone Project/Capstone Project/IDPS/backend/exampleapp/packetTracer/rulesTest/'
    print('BASE PATH = ' + str(basepath))

    import pathlib
    basepath = str(pathlib.Path().absolute()) + '/backend/exampleapp/packetTracer/rulesTest/'
    print('BASE PATH = ' + str(basepath))

    for entry in os.listdir(basepath):
        ruleList, errorCount = RuleFileReader.read(basepath + entry);
        print("\n\nRuleFiles = ", os.path.join(basepath))
        print("\tFinished reading rule file: " + entry)

        if (errorCount == 0):
            print("All (" + str(len(ruleList)) + ") rule/s have been correctly read.")
        else:
            print("\t" + str(len(ruleList)) + " rules have been correctly read:")
            print("\t" + str(errorCount) + " rules have errors and could not be read.\n\n")
        print('RULE LIST = ', ruleList , "\n\n")

    def sniffPackets(self, packet):
        newPacket = None
        global pckNum
        pckNum += 1
        srcMAC = packet[Ether].src
        dstMAC = packet[Ether].dst

        if packet.haslayer(IP):
            protocols = {
                1: 'ICMP',
                4: 'IPv4',
                6: 'TCP',
                17: 'UDP',
                41: 'IPv6',
                56: 'TLSP',
                80: 'HTTP',
                84: 'TTP',
                88: 'EIGRP',
                143: 'ETHERNET',
                443: 'HTTPS'
            }
            flagsTCP = {
                'F': 'FIN',
                'S': 'SYN',
                'R': 'RST',
                'P': 'PSH',
                'A': 'ACK',
                'U': 'URG',
                'E': 'ECE',
                'C': 'CWR',
            }
            pckt_src = packet[IP].src
            pckt_dst = packet[IP].dst
            src_port = ''
            dst_port = ''
            protocol = ''
            seq = 0
            flags = []
            load = ''
            alerts = None

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                seq = packet[TCP].seq
                ack = packet[TCP].ack if packet[TCP].ack else 0
                for flag in packet[TCP].flags:
                    flags.append(flagsTCP[flag])

            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            protocol = protocols[packet[IP].proto] if packet[IP].proto in protocols else ''
            load = packet[IP].load if Raw in packet else ''

            time = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            for rule in ids.ruleList:
                # Check all rules
                matched = rule.match(packet)
                # print('RULE = ' + str(rule) + "\n\n")
                if (matched):
                    print ("Bool? = " + str(matched))
                    print("Matched Rule: " + str(matched))
                    logMessage = rule.getMatchedMessage(packet)
                    logging.warning(logMessage)
                    alerts.append(rule.getMatchedMessage(packet))
                    print(rule.getMatchedPrintMessage(packet) + "\n\n========================================================")

            newPacket = Packet(pckNum, pckt_src, pckt_dst, time, protocol, src_port, dst_port, flags, seq, alerts)
            packet_list[pckNum] = newPacket


            # for rule in ids.ruleList:
            #     # Check all rules
            #     matched = rule.match(packet)
            #     # print('RULE = ' + str(rule) + "\n\n")
            #     if (matched):
            #         print ("Bool? = " + str(matched))
            #         print("Matched Rule: " + str(matched))
            #         logMessage = rule.getMatchedMessage(packet)
            #         logging.warning(logMessage)
            #         alerts.append(rule.getMatchedMessage(packet))
            #         print(rule.getMatchedPrintMessage(packet) + "\n\n========================================================")

        return newPacket

if __name__ == '__main__':


    print("==Custom packet sniffer==")
    ruleList = list()
    sniffer = AsyncSniffer(iface="en0", prn=ids().sniffPackets)
    sniffer.start()
    time.sleep(5)
    print("\n\n==Stopping custom sniffer==")
    sniffer.stop()
