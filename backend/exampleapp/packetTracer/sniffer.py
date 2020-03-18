# from .packet import Packet
import sys, os
import logging

import json
import requests
import urllib.request
from datetime import datetime
import time
from scapy.layers.inet import *
from scapy.all import *
import exampleapp.packetTracer.RuleFileReader as RuleFileReader
from collections import OrderedDict
from exampleapp.packetTracer.packet import Packet
from exampleapp.packetTracer.Rule import Rule
import time
from datetime import datetime
from scapy.layers.inet import UDP

sys.path.append('../')


pckNum = 0
packet_list = OrderedDict()
apikey = '79aa5e1eed184359a87119a5a9dace18'

# class Packet(object):

#     def __init__(self, pcktNumber, srcIP, dstIP, time, proto, srcPort, dstPort, flags, seq, alerts):
#         self.pcktNumber = pcktNumber
#         self.srcIP = srcIP
#         self.dstIP = dstIP
#         self.srcPort = srcPort
#         self.dstPort = dstPort
#         self.time = time
#         self.protocol = proto
#         self.flags = flags
#         self.seq = seq
#         self.alerts = alerts

#     def to_dict(self):
#         return {
#             'num': self.pcktNumber,
#             'srcIP': self.srcIP
#         }

#     def __str__(self):
#         return ("(%d) IP Packet: %s ==>  %s, Time: %s, Protocol: %s, Port: %s --> %s, %s ||| ALERTS  = %s" % (self.pcktNumber, self.srcIP, self.dstIP, self.time, self.protocol, self.srcPort, self.dstPort, self.flags, self.alerts))

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
    basepath = str(pathlib.Path().absolute()) + '/exampleapp/packetTracer/rulesTest/'
    # basepath = str(os.path.dirname) + '/rulesTest/'
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


    def sniffPackets(self, consumer):
        print('IN SNIFF PACKETS')
        def nestedSniff(packet):
            newPacket = None
            global pckNum
            pckNum += 1
            srcMAC = packet[Ether].src
            dstMAC = packet[Ether].dst

            print("running capturing thread")
            """ THIS wrpcap writes the pcap file, uncomment it if you wanna use it """

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
                alerts = []


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
                        # print("Matched Rule: " + str(matched))
                        logMessage = rule.getMatchedMessage(packet)
                        logging.warning(logMessage)
                        print("CREATING ALERT OBJECT -------", rule.createAlertObject(packet, pckNum, time))
                        alerts.append(rule.createAlertObject(packet, pckNum, time).__dict__)
                        # alerts.append(rule.getMatchedMessage(packet))
                        # print(rule.getMatchedPrintMessage(packet) + "\n\n========================================================")

                newPacket = Packet(pckNum, pckt_src, pckt_dst, time, protocol, src_port, dst_port, flags, seq, alerts)
                packet_list[pckNum] = newPacket
                print(newPacket)
                consumer.send(text_data=json.dumps({
                    'message': newPacket.__dict__
                }))

        return nestedSniff

    def detect_TCPflood(self, packet, consumer):
        if packet.haslayer(TCP):
            pckt_src = packet[IP].src
            pckt_dst = packet[IP].dst
            stream = pckt_src + ':' + pckt_dst

            if stream in type(self).__ip_cnt_TCP:
                type(self).__ip_cnt_TCP[stream] += 1
            else:
                type(self).__ip_cnt_TCP[stream] = 1

            for stream in type(self).__ip_cnt_TCP:
                pckts_sent = type(self).__ip_cnt_TCP[stream]
                if pckts_sent > type(self).__THRESH:
                    src = stream.split(':')[0]
                    dst = stream.split(':')[1]

                    consumer.send(text_data=json.dumps({
                        'message': "Possible Flooding Attack from %s --> %s" % (src, dst)
                    }))
                    # print("Possible Flooding Attack from %s --> %s" % (src, dst))

    # def startSniff(self):
    #     sniff(filter="ip", iface="en0", prn=ids().sniffPackets)

# if __name__ == '__main__':
#     print("custom packet sniffer ")
#     # sniff(filter="ip")
