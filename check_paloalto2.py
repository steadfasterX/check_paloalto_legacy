#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Ralph Offinger, Thomas Fischer'

######################################################################################
#
# Check Palo Alto
#
# Purpose:		    Check Palo Alto Firewall systems. Tested in PA-500 v6.0.1
# It is based on the PA REST API and the Nagios Plugin library 1.22.
#                   (https://pypi.python.org/pypi/nagiosplugin/)
#
#
# Last modified: 	2015-02-25 by Ralph Offinger
# License:		    CC BY-ND 3.0 (http://creativecommons.org/licenses/by-nd/3.0/)
#
#######################################################################################

import argparse
import logging
import urllib.request
import time
import sys
import re
from xml.etree import ElementTree as ET

import nagiosplugin


_log = logging.getLogger('nagiosplugin')

# The REST API requires a token to get information. This token must be generated once.
# 1) Create a "monitoring role" in the PA.
# 2) Disable everything in the WEB UI tab within that role
# 3) Enable "Operational requests" in the XML API tab and disable everything else
# 4) Ensure that the tab "Command line" is "None"
# 5) Create a new Admin user who uses that custom role and for best practices choose
# at least 20 length password without special characters other than '_-'
# 6) Generating the token is easy. To do that login to your PA with the monitoring user
# and open:
# https://x.x.x.x/api/?type=keygen&user=YOUR-USERNAME&password=YOUR-PASSWORD
# (replace YOUR-USERNAME with the username created in step 5) and YOUR-PASSWORD accordingly)

#########################################################################################
# no changes behind this point
#########################################################################################

# data acquisition

class DiskSpace(nagiosplugin.Resource):
    def __init__(self, host, token):
        self.host = host
        self.token = token

    def probe(self):
        """
        Meaning:    Will fetch the PA Diskspace from the REST API
        Args:       Palo Alto as hostname or FQDN (required)
        """
        _log.info('reading load from REST-API')

        cmdDiskSpace = '<show><system><disk-space><%2Fdisk-space><%2Fsystem><%2Fshow>'
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmdDiskSpace
        with urllib.request.urlopen(requestURL) as url:
            root = ET.parse(url).getroot()

        item = root.find('result').text

        disks = re.findall('sda\d.*', item)

        for disk in disks:
            percent = int(re.findall('([0-9]+%)', disk)[0].replace("%", ""))
            sda = re.findall('(sda\d)', disk)[0]
            yield nagiosplugin.Metric(sda, percent, min=0, max=100,
                                      context='diskspace')


# data presentation

class DiskSpaceSummary(nagiosplugin.Summary):
    def ok(self, results):
        return 'Used Diskspace is %s' % (', '.join(
            str(results[r].metric) + '%' for r in ['sda2', 'sda5', 'sda6', 'sda8']))


# data acquisition

class SessInfo(nagiosplugin.Resource):
    def __init__(self, host, token):
        self.host = host
        self.token = token

    def probe(self):
        """
        Meaning:    Will fetch the maximum possible sessions, the number of current sessions and the throughput
                    from the REST API
        Args:       Palo Alto as hostname or FQDN (required)
        """
        _log.info('reading load from REST-API')

        cmdSession = '%3Cshow%3E%3Csession%3E%3Cinfo%3E%3C%2Finfo%3E%3C%2Fsession%3E%3C%2Fshow%3E'

        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmdSession

        with urllib.request.urlopen(requestURL) as url:
            root = ET.parse(url).getroot()

        for item in root.findall('result'):
            maxsess = int(item.find('num-max').text)
            actsess = int(item.find('num-active').text)
            throughput = int(item.find('kbps').text)

        return [nagiosplugin.Metric('maxsess', maxsess, min=0),
                nagiosplugin.Metric('actsess', actsess, min=0),
                nagiosplugin.Metric('throughput', throughput, 'B', min=0)]


# data presentation

class SessSummary(nagiosplugin.Summary):
    def ok(self, results):
        return 'Max possible sessions: ' + str(results['maxsess'].metric) + ' / Active sessions: ' + str(results[
                                                                                                             'actsess'].metric) + ' / Throughput in kbps: ' + str(
            results['throughput'].metric)


# data acquisition

class Load(nagiosplugin.Resource):
    def __init__(self, host, token):
        self.host = host
        self.token = token

    def probe(self):
        """
        Meaning:    Will fetch the CPU Load from the REST API
        Args:       Palo Alto as hostname or FQDN (required)
        """
        _log.info('reading load from REST-API')

        cmdCPU = '<show><running><resource-monitor><minute><last>1<%2Flast>' \
                 '<%2Fminute><%2Fresource-monitor><%2Frunning><%2Fshow>'
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmdCPU

        with urllib.request.urlopen(requestURL) as url:
            root = ET.parse(url).getroot()

        cpuavg = root.find('.//cpu-load-average')

        for entry in cpuavg.findall('entry'):
            coreid = int(entry.find('coreid').text)
            cpuLoad = float(entry.find('value').text)
            yield nagiosplugin.Metric('CPU%d' % coreid, cpuLoad / 100, min=0,
                                      context='load')


# data presentation

class LoadSummary(nagiosplugin.Summary):
    def ok(self, results):
        return 'loadavg is %s' % (', '.join(
            str(results[r].metric) for r in ['CPU0', 'CPU1', 'CPU2', 'CPU3']))


# data acquisition

class Throughput(nagiosplugin.Resource):
    statefile = '/usr/lib/nagios/plugins/checkpa/throughput'
    #statefile = 'throughput'

    def __init__(self, host, token, interface, prefix):
        self.host = host
        self.token = token
        self.interface = interface
        self.prefix = prefix


    def probe(self):
        """
        Meaning:    Will fetch the throughput of the VPN Tunnels or the ethernet connections from the REST-API.
        Args:       Palo Alto as hostname or FQDN (required), specific interface and the prefix.
        """

        id = self.prefix + str(self.interface)
        currentTime = time.time()
        if self.prefix == 'eth':
            cmdThroughput = '<show><counter><interface>ethernet1/' + str(
                self.interface) + '</interface></counter></show>'
        elif self.prefix == 'tun':
            cmdThroughput = '<show><counter><interface>tunnel.' + str(self.interface) + '</interface></counter></show>'
        else:
            print('Unknown prefix!')
            sys.exit(3)
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmdThroughput

        with urllib.request.urlopen(requestURL) as url:
            root = ET.parse(url).getroot()

        iBytesNew = 0
        oBytesNew = 0

        for item in root.findall('.//entry'):
            iBytesNew = item.find('ibytes').text
            oBytesNew = item.find('obytes').text

        with nagiosplugin.Cookie(self.statefile) as cookie:
            oldInBytes = cookie.get(id + 'i', iBytesNew)
            oldOutBytes = cookie.get(id + 'o', oBytesNew)
            oldTime = cookie.get(id + 't', currentTime)
            cookie[id + 'i'] = iBytesNew
            cookie[id + 'o'] = oBytesNew
            cookie[id + 't'] = currentTime

        difftime = currentTime - oldTime
        if difftime > 0:
            diffinbytes = round((float(iBytesNew) - float(oldInBytes)) / difftime, 2)
            diffoutbytes = round((float(oBytesNew) - float(oldOutBytes)) / difftime, 2)
        else:
            diffinbytes = 0
            diffoutbytes = 0

        return [nagiosplugin.Metric('inBytes', diffinbytes, 'B', min=0),
                nagiosplugin.Metric('outBytes', diffoutbytes, 'B', min=0)]


# data presentation

class NetworkSummary(nagiosplugin.Summary):
    def ok(self, results):
        kiBIn = round(results['inBytes'].metric.value / 1000, 2)
        kiBOut = round(results['outBytes'].metric.value / 1000, 2)
        return 'Input is %s' % str(kiBIn) + 'kbps - Output is %s' % str(kiBOut) + 'kbps'


# runtime environment and data evaluation

@nagiosplugin.guarded
def main():
    argp = argparse.ArgumentParser(description=__doc__)
    argp.add_argument('-w', '--warning', metavar='RANGE', default='',
                      help='return warning if load is outside RANGE')
    argp.add_argument('-c', '--critical', metavar='RANGE', default='',
                      help='return critical if load is outside RANGE')
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')
    argp.add_argument('-T', '--token', default='',
                      help='Token for PaloAlto')
    argp.add_argument('-H', '--host', default='',
                      help='PaloAlto Host')
    argp.add_argument('-C', '--check', default='',
                      help='PaloAlto Check-Command. Available Commands: '
                           'CPU, DiskSpace, SessInfo, EthThroughput, VPNThroughput')
    argp.add_argument('-I', '--interface', type=int, nargs='?',
                      help='PaloAlto specific interface for EthThroughput and VPNThroughput.')
    args = argp.parse_args()
    if args.check == 'CPU':
        check = nagiosplugin.Check(
            Load(args.host, args.token),
            nagiosplugin.ScalarContext('load', args.warning, args.critical),
            LoadSummary())
    elif args.check == 'DiskSpace':
        check = nagiosplugin.Check(
            DiskSpace(args.host, args.token),
            nagiosplugin.ScalarContext('diskspace', args.warning, args.critical),
            DiskSpaceSummary())
    elif args.check == 'SessInfo':
        check = nagiosplugin.Check(
            SessInfo(args.host, args.token),
            nagiosplugin.ScalarContext('maxsess', args.warning, args.critical),
            nagiosplugin.ScalarContext('actsess', args.warning, args.critical),
            nagiosplugin.ScalarContext('throughput', args.warning, args.critical),
            SessSummary())
    elif args.check == 'EthThroughput':
        if not args.interface:
            argp.print_help()
            sys.exit(0)
        else:
            check = nagiosplugin.Check(
                Throughput(args.host, args.token, args.interface, 'eth'),
                nagiosplugin.ScalarContext('inBytes', args.warning, args.critical),
                nagiosplugin.ScalarContext('outBytes', args.warning, args.critical),
                NetworkSummary())
    elif args.check == 'VPNThroughput':
        if not args.interface:
            argp.print_help()
            sys.exit(0)
        else:
            check = nagiosplugin.Check(
                Throughput(args.host, args.token, args.interface, 'tun'),
                nagiosplugin.ScalarContext('inBytes', args.warning, args.critical),
                nagiosplugin.ScalarContext('outBytes', args.warning, args.critical),
                NetworkSummary())
    else:
        argp.print_help()
    check.main(verbose=args.verbose)


if __name__ == '__main__':
    main()
