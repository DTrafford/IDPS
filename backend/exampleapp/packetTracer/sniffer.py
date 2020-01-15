# from .packet import Packet
import json
import requests
import urllib.request
from datetime import datetime
from scapy.layers.inet import *
from scapy.all import *
import sys

sys.path.append('../')


apikey = '79aa5e1eed184359a87119a5a9dace18'

class Packet(object):

    def __init__(self, srcIP, srcCity, srcCountry, srcContinent, dstIP, dstCity, dstCountry, dstContinent, time):
        self.srcIP = srcIP
        self.srcCity = srcCity
        self.srcCountry = srcCountry
        self.srcContinent = srcContinent
        self.dstIP = dstIP
        self.dstCity = dstCity
        self.dstCountry = dstCountry
        self.dstContinent = dstContinent
        self.srcPort = ''
        self.dstPort = ''
        self.time = time

    def _addPorts(self, srcPort, dstPort):
        self.srcPort = srcPort
        self.dstPort = dstPort

    def __str__(self):
        return ("IP Packet: %s (%s) ==>  %s (%s), Time: %s, Port: %s --> %s, " % (self.srcIP, self.srcCountry, self.dstIP, self.dstCountry, self.time, self.srcPort, self.dstPort))
        # print("IP Packet: %s (%s) ==>  %s (%s)" % (self.srcIP, self.srcCountry, self.dstIP, self.dstCountry), end=' ')


""" 
ALL AVAILABLE FIELDS FROM ipgeolcation.io result

{'ip': '8.8.8.8', 'continent_code': 'NA', 'continent_name': 'North America', 'country_code2': 'US', 'country_code3': 'USA', 
'country_name': 'United States', 'country_capital': 'Washington', 'state_prov': 'California', 'district': 'Santa Clara County', 
'city': 'Mountain View', 'zipcode': '94041', 'latitude': '37.42290', 'longitude': '-122.08500', 'is_eu': False, 'calling_code': '+1', 
'country_tld': '.us', 'languages': 'en-US,es-US,haw,fr', 'country_flag': 'https://ipgeolocation.io/static/flags/us_64.png', 
'geoname_id': '5375480', 'isp': 'Level 3 Communications', 'connection_type': 'wired', 'organization': 'Google LLC', 
'currency': {'code': 'USD', 'name': 'US Dollar', 'symbol': '$'}, 'time_zone': {'name': 'America/Los_Angeles', 'offset': -8, 
'current_time': '2019-09-05 15:56:29.568-0700', 'current_time_unix': 1567724189.568, 'is_dst': True, 'dst_savings': 1}}
"""

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

    def sniffPackets(self, consumer):
        print('IN SNIFF PACKETS')
        def nestedSniff(packet):
            newPacket = {
            }
            # print(packet.summary())
            print("running capturing thread")

            if packet.haslayer(ICMP):
                consumer.send(text_data=json.dumps({
                    'message': "IN ICMP"
                }))
                newPacket['srcIP'] = packet[IP].src
                newPacket['dstIP'] = packet[IP].dst
                # srcCountryFlag = ''
                # srcContinent = ''
                # srcCity = ''
                # srcPort = ''
                # dstCountry = ''
                # dstCountryFlag = ''
                # dstContinent = ''
                # dstCity = ''
                # dstPort = ''
                newPacket['time'] = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                # newPacket = Packet(pckt_src, srcCity, srcCountry, srcContinent, pckt_dst, dstCity, dstCountry, dstContinent,
                #                    time)

            if packet.haslayer(IP):
                newPacket['srcIP'] = packet[IP].src
                newPacket['dstIP'] = packet[IP].dst
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

                src_location_api = 'https://api.ipgeolocation.io/ipgeo?apiKey={x}&ip={y}'.format(
                    x=apikey, y=newPacket['srcIP'])
                r = requests.get(src_location_api)
                result = r.json()
                # print(result)
                if 'city' in result:
                    newPacket['srcCountry'] = result['country_name']
                    # srcCountryFlag = result['country_flag']
                    # srcContinent = result['continent_name']
                    # srcCity = result['city']
                # else:
                #     return

                dst_location_api = 'https://api.ipgeolocation.io/ipgeo?apiKey={x}&ip={y}'.format(
                    x=apikey, y=newPacket['dstIP'])
                r = requests.get(src_location_api)
                result = r.json()
                if 'city' in result:
                    newPacket['dstCountry'] = result['country_name']
                    # dstCountryFlag = result['country_flag']
                    # dstContinent = result['continent_name']
                    # dstCity = result['city']

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
                newPacket['time'] = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                # newPacket = Packet(pckt_src, srcCity, srcCountry, srcContinent, pckt_dst, dstCity, dstCountry, dstContinent, time)
                # print("IP Packet: %s ==>  %s, %s" % (pckt_src, pckt_dst, str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))), end=' ')

                # print(newPacket, end=' ')

            if packet.haslayer(TCP):
                newPacket['srcPort'] = packet.sport
                newPacket['dstPort'] = packet.dport
                jsonPacket = json.dumps(newPacket);
                # print(newPacket)
                consumer.send(text_data=json.dumps({
                    'message': newPacket
                }))
                self.detect_TCPflood(packet, consumer)
            else:
                print()

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
