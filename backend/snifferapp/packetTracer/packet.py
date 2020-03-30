class Packet(object):

    def __init__(self, pcktNumber, srcIP, dstIP, time, proto, srcPort, dstPort, flags, seq, alerts):
        self.pcktNumber = pcktNumber
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.time = time
        self.protocol = proto
        self.flags = flags
        self.seq = seq
        self.alerts = alerts
        # self.srcCity = srcCity
        # self.srcCountry = srcCountry
        # self.srcContinent = srcContinent
        # self.dstCity = dstCity
        # self.dstCountry = dstCountry
        # self.dstContinent = dstContinent

    def to_dict(self):
        return {
            'num': self.pcktNumber,
            'srcIP': self.srcIP
        }

    def __str__(self):
        return ("(%d) IP Packet: %s ==>  %s, Time: %s, Protocol: %s, Port: %s --> %s, %s ||| ALERTS  = %s" % (self.pcktNumber, self.srcIP, self.dstIP, self.time, self.protocol, self.srcPort, self.dstPort, self.flags, self.alerts))


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
