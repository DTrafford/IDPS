import sys, os
# sys.path.append('../')

import glob
from threading import Thread
import logging

from IPython.core.magic_arguments import magic_arguments
from scapy.all import *
from datetime import datetime
import urllib.request
import requests
import json
import pandas as pd
from parsuricata import parse_rules
import RuleFileReader
from collections import OrderedDict
from packet import Packet
from Rule import Rule

import time
from datetime import datetime

# print("This file full path (following symlinks)")
# path = os.path.realpath('./backend/exampleapp/packetTracer/rules/*.rules')
# print(path + "\n")
from scapy.layers.inet import UDP

pckNum = 0
# df = pd.DataFrame()
packet_list = OrderedDict()
apikey = '79aa5e1eed184359a87119a5a9dace18'

# ruleList = []

# import pathlib
# basepath = str(pathlib.Path().absolute()) + '/backend/exampleapp/packetTracer/rulesTest/'
# print('BASE PATH = ' + str(basepath))

# for entry in os.listdir(basepath):
#     # ruleList.append(RuleFileReader.read(basepath + entry));
#     # ruleList.append(parse_rules(entry))
#     # ruleList.append(RuleFileReader.read(filename));
#     ruleList, errorCount = RuleFileReader.read(basepath + entry);
#     print("\n\nRuleFiles = ", os.path.join(basepath))
#     print("\tFinished reading rule file: " + entry)

#     if (errorCount == 0):
#         print("All (" + str(len(ruleList)) + ") rule/s have been correctly read.")
#     else:
#         print("\t" + str(len(ruleList)) + " rules have been correctly read:")
#         print("\t" + str(errorCount) + " rules have errors and could not be read.\n\n")
#         for x in ruleList:
#             print(x)

# print('RULE LIST = ', ruleList)
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
    # __protocols = {
    #     1: 'ICMP',
    #     4: 'IPv4',
    #     6: 'TCP',
    #     17: 'UDP',
    #     41: 'IPv6'
    # }

    __ip_cnt_TCP = {}  # ip address requests counter

    __THRESH = 1000

    now = datetime.now()
    current_file = 'captured_pkts' + str(now) + '.pcap'

    ruleList = []

    import pathlib
    basepath = 'X:/CyberSecurity/CBER710-Capsone Project/Capstone Project/IDPS/backend/exampleapp/packetTracer/rulesTest/'
    print('BASE PATH = ' + str(basepath))

    for entry in os.listdir(basepath):
        # ruleList.append(RuleFileReader.read(basepath + entry));
        # ruleList.append(parse_rules(entry))
        # ruleList.append(RuleFileReader.read(filename));
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
        # global ruleList
        #print("RULE LIST INSIDE SNIFF PACKETS = ", ids.ruleList)
        newPacket = None
        global pckNum
        pckNum += 1
        srcMAC = packet[Ether].src
        dstMAC = packet[Ether].dst
        # print(srcMAC)
        # print(packet)
        # df.append(packet)
        # dh.head()
        # print(packet.sprintf("Source IP: %IP.src% () ==> Dest IP: %IP.dst% (), Proto: %IP.proto%, Flags: %TCP.flags%").upper())

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

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                seq = packet[TCP].seq
                ack = packet[TCP].ack if packet[TCP].ack else 0
                # print('({}) TCP PAYLOAD = {}'.format(pckNum, packet[TCP].payload))
                # print('({}) TCP PAYLOAD LENGTH = {}'.format(pckNum, len(packet[TCP].payload)))
                # ack = packet[TCP].ack
                # print(ack)
                for flag in packet[TCP].flags:
                    flags.append(flagsTCP[flag])

            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            protocol = protocols[packet[IP].proto] if packet[IP].proto in protocols else ''
            # if packet[IP].proto in protocols:
            #     protocol = protocols[packet[IP].proto]

            load = packet[IP].load if Raw in packet else ''
            # if Raw in packet:
            # print('LOAD = ', load)
            """ To get the location of the source and destination ip addresses """
            #     load = packet[IP].load


            # src_location_api = 'https://api.ipgeolocation.io/ipgeo?apiKey={x}&ip={y}'.format(x=apikey, y=pckt_src)
            # r = requests.get(src_location_api)
            # result = r.json()

            # if 'city' in result:
            #     srcCountry = result['country_name']
            #     srcCountryFlag = result['country_flag']
            #     srcContinent = result['continent_name']
            #     srcCity = result['city']

            # dst_location_api = 'https://api.ipgeolocation.io/ipgeo?apiKey={x}&ip={y}'.format(x=apikey, y=pckt_dst)
            # r = requests.get(src_location_api)
            # result = r.json()
            # if 'city'in result:
            #     dstCountry = result['country_name']
            #     dstCountryFlag = result['country_flag']
            #     dstContinent = result['continent_name']
            #     dstCity = result['city']

            time = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            newPacket = Packet(pckNum, pckt_src, pckt_dst, time, protocol, src_port, dst_port, flags, seq)
            packet_list[pckNum] = newPacket


            for rule in ids.ruleList:
                # Check all rules
                matched = rule.match(packet)
                print('RULE = ' + str(rule) + "\n\n")
                if (matched):
                    print ("Bool? = " + str(matched))
                    print("Matched Rule: " + str(matched))
                    logMessage = rule.getMatchedMessage(packet)
                    logging.warning(logMessage)
                    print(rule.getMatchedPrintMessage(packet) + "\n\n========================================================")


                    # print('PACKET DETAILS = ', packet_list[pckNum])
            # if 'SYN' and 'ACK' in newPacket.flags:
            #     print('SYN & ACK PACKET')
            #     for i in range(pckNum, 0, -1):
            #         print(i)

            # for obj in packet_list.values():
            #    if obj.srcIP == newPacket.srcIP:
            #        print('matched')
            # print('PACKET LIST = ', packet_list)
            # df.add(dfPacket)
            # print(df.head())

        # print('TEST 1  = ', newPacket)
        return newPacket

    # def detect_TCPflood(self, packet):
    #     if packet.haslayer(TCP):
    #         pckt_src = packet[IP].src
    #         pckt_dst = packet[IP].dst
    #         stream = pckt_src + ':' + pckt_dst

    #         if stream in type(self).__ip_cnt_TCP:
    #             type(self).__ip_cnt_TCP[stream] += 1
    #         else:
    #             type(self).__ip_cnt_TCP[stream] = 1

    #         for stream in type(self).__ip_cnt_TCP:
    #             pckts_sent = type(self).__ip_cnt_TCP[stream]
    #             if pckts_sent > type(self).__THRESH:
    #                 src = stream.split(':')[0]
    #                 dst = stream.split(':')[1]
    #                 print("Possible Flooding Attack from %s --> %s" % (src, dst))


if __name__ == '__main__':


    print("==Custom packet sniffer==")
    ruleList = list()
    sniffer = AsyncSniffer(iface="Wi-Fi", prn=ids().sniffPackets)
    # sniffer = AsyncSniffer(iface="Wi-Fi", prn=ids().sniffPackets)
    #sniffer = AsyncSniffer(iface="Wi-Fi", prn=ids.inPacket,filter="", store=0, stop_filter=self.stopfilter)
    sniffer.start()

    #print("__________________________________________________________________________________________________________")
    #print("     |        Src and Dest IP         |         Time:       | Protocol |      Port     |     Flags        | Sequence")
    time.sleep(5)
    print("\n\n==Stopping custom sniffer==")
    sniffer.stop()
