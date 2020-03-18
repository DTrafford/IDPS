"""Functions for reading a file of rules."""

from exampleapp.packetTracer.Action import *
# from Action import *
from exampleapp.packetTracer.Protocol import *
# from Protocol import *
from exampleapp.packetTracer.IPNetwork import *
# from IPNetwork import *
from exampleapp.packetTracer.Ports import *
# from Ports import *
from exampleapp.packetTracer.Rule import *
# from Rule import *

def read(filename):
    """Read the input file for rules and return the list of rules and the number of line errors."""

    l = list()
    with open (filename, 'r') as f:
        ruleErrorCount = 0
        for line in f:
            #rule = parseRule(line)

            try:
                rule = Rule(line)
                l.append(rule)
            except ValueError as err:
                ruleErrorCount += 1
                print(err)

    #return l
    return l, ruleErrorCount
