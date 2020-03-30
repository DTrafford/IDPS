class Alert(object):

    def __init__(self, pckNum, msg, rule, srcIP, srcPort, dstIP, dstPort, time):
        self.pckNum = pckNum
        self.msg = msg
        self.rule = rule
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.time = time

    def __str__(self):
        return ("(%d) ALERT MESSAGE: %s FOR IP Packet: %s ==>  %s, Time: %s, Port: %s --> %s ||| RULE  = %s" % (self.pckNum, self.msg, self.srcIP, self.dstIP, self.time, self.srcPort, self.dstPort, self.rule))
