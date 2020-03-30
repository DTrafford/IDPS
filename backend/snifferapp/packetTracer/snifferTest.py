import sys
import os

import glob

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

import time
from datetime import datetime
import pathlib

rules = []

basepath = str(pathlib.Path().absolute()) + \
    '/backend/snifferapp/packetTracer/rulesTest/'
print('BASE PATH = ' + str(basepath))
for entry in os.listdir(basepath):
    rules.append(RuleFileReader.read(str(basepath) + entry))

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

            """ To get the location of the source and destination ip addresses """

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
            newPacket = Packet(pckNum, pckt_src, pckt_dst,
                               time, protocol, src_port, dst_port, flags, seq)

            packet_list[pckNum] = (newPacket)

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
    print("custom packet sniffer ")
    sniffer = AsyncSniffer(iface="en0", prn=ids().sniffPackets)
    sniffer.start()
    time.sleep(5)
    print("Stopping sniffer")
    sniffer.stop()

