import sys
sys.path.append('../')

from scapy.all import *
from datetime import datetime
import urllib.request
import requests
import json
from packet import Packet

import time
from datetime import datetime

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
        # wrpcap("captured_pkts.pcap" + str(now) , packet, append = True)
        wrpcap(ids.current_file, packet, append = True)
        # print(packet.summary())
        # print(packet.sprintf("Source IP: %IP.src% () ==> Dest IP: %IP.dst% (), Proto: %IP.proto%, Flags: %TCP.flags%").upper())
        # newPacket = Packet(IP.src)
        # print(newPacket)
        if packet.haslayer(ICMP):
            print('IN ICMP')
            pckt_src = packet[IP].src
            pckt_dst = packet[IP].dst
            srcCountry = ''
            srcCountryFlag = ''
            srcContinent = ''
            srcCity = ''
            srcPort = ''
            dstCountry = ''
            dstCountryFlag = ''
            dstContinent = ''
            dstCity = ''
            dstPort = ''
            time = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            newPacket = Packet(pckt_src, srcCity, srcCountry, srcContinent, pckt_dst, dstCity, dstCountry, dstContinent, time)
            
        if packet.haslayer(IP):
            pckt_src = packet[IP].src
            pckt_dst = packet[IP].dst
            srcCountry = ''
            srcCountryFlag = ''
            srcContinent = ''
            srcCity = ''
            srcPort = ''
            dstCountry = ''
            dstCountryFlag = ''
            dstContinent = ''
            dstCity = ''
            dstPort = ''
            """ To get the location of the source and destination ip addresses """

            src_location_api = 'https://api.ipgeolocation.io/ipgeo?apiKey={x}&ip={y}'.format(x=apikey, y=pckt_src)
            r = requests.get(src_location_api)
            result = r.json()
            # print(result)
            if 'city' in result:
                srcCountry = result['country_name']
                srcCountryFlag = result['country_flag']
                srcContinent = result['continent_name']
                srcCity = result['city']
            # else:
            #     return

            dst_location_api = 'https://api.ipgeolocation.io/ipgeo?apiKey={x}&ip={y}'.format(x=apikey, y=pckt_dst)
            r = requests.get(src_location_api)
            result = r.json()
            if 'city'in result:
                dstCountry = result['country_name']
                dstCountryFlag = result['country_flag']
                dstContinent = result['continent_name']
                dstCity = result['city']

            #######################
            # src_location_api = "https://www.iplocate.io/api/lookup/" + pckt_src
            # dst_location_api = "https://www.iplocate.io/api/lookup/" + pckt_dst       
            # resp = urllib.request.urlopen(src_location_api)
            # result = resp.read()
            # result = json.loads(result.decode('utf-8'))
            # srcCountry = result['country']
            # srcContinent = result['continent']
            # srcCity = result['city']
            # resp = urllib.request.urlopen(dst_location_api)
            # result = resp.read()
            # result = json.loads(result.decode('utf-8'))
            # dstCountry = result['country']
            # dstContinent = result['continent']
            # dstCity = result['city']
            time = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            newPacket = Packet(pckt_src, srcCity, srcCountry, srcContinent, pckt_dst, dstCity, dstCountry, dstContinent, time)
            # print("IP Packet: %s ==>  %s, %s" % (pckt_src, pckt_dst, str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))), end=' ')

            # print(newPacket, end=' ')

        if packet.haslayer(TCP):
            src_port = packet.sport
            dst_port = packet.dport
            ports = ''
            newPacket._addPorts(src_port, dst_port)
            print(newPacket, end=' ')
            # print(", Port: %s --> %s, " % (src_port, dst_port), end='')
            print([type(self).__flagsTCP[x]
                   for x in packet.sprintf('%TCP.flags%')])
            self.detect_TCPflood(packet)
        else:
            print()

        print(newPacket)
        return newPacket

    def detect_TCPflood(self, packet):
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
                    print("Possible Flooding Attack from %s --> %s" % (src, dst))

    # def startSniff(self):
    #     sniff(filter="ip", iface="en0", prn=ids().sniffPackets)
    
if __name__ == '__main__':
    print("custom packet sniffer ")
    # sniff(filter="ip")
    # sniff(iface="en0", prn=ids().sniffPackets)
    sniffer = AsyncSniffer(iface="en0", prn=ids().sniffPackets)
    sniffer.start()
    time.sleep(5)
    print("Stopping sniffer")
    sniffer.stop()




