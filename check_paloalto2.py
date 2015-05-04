#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Ralph Offinger, Thomas Fischer'

######################################################################################
#
# Check Palo Alto
#
# Purpose: Check Palo Alto Firewall systems. Tested in PA-500 v6.0.1
# It is based on the PA REST API and the Nagios Plugin library 1.22.
# (https://pypi.python.org/pypi/nagiosplugin/)
#
#
# Last modified: 2015-03-10 by Ralph Offinger
# License: CC BY-ND 3.0 (http://creativecommons.org/licenses/by-nd/3.0/)
#
#######################################################################################

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
#
# On PA-Update or reset please delete the throughput file in /usr/lib/nagios/plugins/checkpa/

import argparse
import logging
import urllib.request
import time
import sys
import re
from xml.etree import ElementTree as ET

import nagiosplugin


_log = logging.getLogger('nagiosplugin')


class DiskSpace(nagiosplugin.Resource):
    def __init__(self, host, token):
        self.host = host
        self.token = token

    def probe(self):
        """
        Meaning:    Will fetch the PA Diskspace from the REST API
        Args:       Palo Alto as hostname or FQDN (required)
        """
        _log.info('reading disk space from REST-API')

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


class DiskSpaceSummary(nagiosplugin.Summary):
    def ok(self, results):
        return 'Used Diskspace is %s' % (', '.join(
            str(results[r].metric) + '%' for r in ['sda3', 'sda5', 'sda6', 'sda8']))


class Environmental(nagiosplugin.Resource):
    def __init__(self, host, token):
        self.host = host
        self.token = token

    def probe(self):
        """
        Meaning:    Will fetch the PA environmentals from the REST API
        Args:       Palo Alto as hostname or FQDN (required)
        """
        _log.info('reading environmental status from REST-API')

        cmdEnvironmental = '<show><system><environmentals></environmentals></system></show>'
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmdEnvironmental
        with urllib.request.urlopen(requestURL) as url:
            root = ET.parse(url).getroot()

        items = root.find('result')

        for item in items:
            items2 = item.findall('.//entry')
            for item2 in items2:
                alarm = item2.find('alarm').text
                if alarm == 'True':
                    return [nagiosplugin.Metric(item.tag, True, context='alarm')]
        return [nagiosplugin.Metric(item.tag, False, context='alarm')]


class EnvironmentalContext(nagiosplugin.Context):
    def __init__(self, name, warning=None, critical=None, fmt_metric=None,
                 result_cls=nagiosplugin.result.Result):

        super(EnvironmentalContext, self).__init__(name, fmt_metric, result_cls)

    def evaluate(self, metric, resource):
        if metric.value is None:
            return self.result_cls(nagiosplugin.state.Unknown, None, metric)
        if metric.value:
            return self.result_cls(nagiosplugin.state.Critical, None, metric)
        else:
            return self.result_cls(nagiosplugin.state.Ok, None, metric)


class EnvironmentalSummary(nagiosplugin.Summary):
    def problem(self, results):
        return 'Alarm found: %s' % str(results[0].metric.name)


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
        _log.info('reading session info from REST-API')

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


class SessSummary(nagiosplugin.Summary):
    def ok(self, results):
        return 'Max possible sessions: ' + str(results['maxsess'].metric) + ' / Active sessions: ' + \
               str(results['actsess'].metric) + ' / Throughput in kbps: ' + str(results['throughput'].metric)


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


class LoadSummary(nagiosplugin.Summary):
    def ok(self, results):
        return 'loadavg is %s' % (', '.join(
            str(results[r].metric) for r in ['CPU0', 'CPU1', 'CPU2', 'CPU3']))


class Throughput(nagiosplugin.Resource):
    statefile = '/usr/lib/nagios/plugins/checkpa/throughput'
    # statefile = 'throughput'

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
        _log.info('reading throughput from REST-API')

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

        for item in root.findall('.//entry'):
            api_inbytes = item.find('ibytes').text
            api_outbytes = item.find('obytes').text

        with nagiosplugin.Cookie(self.statefile) as cookie:
            old_inbytes = cookie.get(id + 'i', api_inbytes)
            old_outbytes = cookie.get(id + 'o', api_outbytes)
            old_time = cookie.get(id + 't', currentTime)

            # simple error handling
            if float(api_inbytes) < float(old_inbytes) or not api_inbytes:
                print('Couldn\'t get a valid input value!')
                sys.exit(3)
            if float(api_outbytes) < float(old_outbytes) or not api_outbytes:
                print('Couldn\'t get a valid output value!')
                sys.exit(3)
            cookie[id + 'i'] = api_inbytes
            cookie[id + 'o'] = api_outbytes
            cookie[id + 't'] = currentTime

        diff_time = float(currentTime) - float(old_time)
        if diff_time > 0:
            diff_inbit = round(((float(api_inbytes) - float(old_inbytes)) / diff_time) * 8, 2)
            diff_outbit = round(((float(api_outbytes) - float(old_outbytes)) / diff_time) * 8, 2)
        else:
            sys.exit(3)

        return [nagiosplugin.Metric('inBytes' + str(self.interface), diff_inbit, 'b', min=0),
                nagiosplugin.Metric('outBytes' + str(self.interface), diff_outbit, 'b', min=0)]


class NetworkSummary(nagiosplugin.Summary):
    def ok(self, results):
        kiBIn, kiBOut = 0, 0
        for result in results:
            if not str(result).find("inBytes"):
                kiBIn += result.metric.value
            else:
                kiBOut += result.metric.value
        return 'Input is %s' % str(round(kiBIn / 1000 / 1000, 2)) + ' Mb/s - ' \
                                                                    'Output is %s' % str(
            round(kiBOut / 1000 / 1000, 2)) + ' Mb/s'


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
                      help='PaloAlto Check-Command. Available commands: '
                           'CPU, DiskSpace, SessInfo, Throughput, Environmental')
    argp.add_argument('-I', '--interface', nargs='?',
                      help='PaloAlto specific interface for Throughput.')
    argp.add_argument('-it', '--interfacetype', nargs='?',
                      help='PaloAlto interface type. Available commands: '
                           'eth, tun')
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
    elif args.check == 'Environmental':
        check = nagiosplugin.Check(
            Environmental(args.host, args.token),
            EnvironmentalContext('alarm'),
            EnvironmentalSummary())
    elif args.check == 'SessInfo':
        check = nagiosplugin.Check(
            SessInfo(args.host, args.token),
            nagiosplugin.ScalarContext('maxsess', args.warning, args.critical),
            nagiosplugin.ScalarContext('actsess', args.warning, args.critical),
            nagiosplugin.ScalarContext('throughput', args.warning, args.critical),
            SessSummary())
    elif args.check == 'Throughput':
        if not args.interface:
            argp.print_help()
            sys.exit(0)
        if not args.interfacetype:
            argp.print_help()
            sys.exit(0)
        else:
            interfaces = str(args.interface).split(",")
            check = nagiosplugin.Check()
            for interface in interfaces:
                check.add(Throughput(args.host, args.token, interface, str(args.interfacetype)))
            for interface in interfaces:
                check.add(nagiosplugin.ScalarContext('inBytes' + interface, args.warning, args.critical))
            for interface in interfaces:
                check.add(nagiosplugin.ScalarContext('outBytes' + interface, args.warning, args.critical))
            check.add(NetworkSummary())
    else:
        argp.print_help()
        sys.exit(0)
    check.main(verbose=args.verbose)


if __name__ == '__main__':
    main()
