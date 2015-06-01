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

import argparse
import logging
import urllib.request
import time
import sys
import re
import tempfile
import nagiosplugin
import os
from datetime import datetime
from xml.etree import ElementTree as ET

from nagiosplugin.result import Result
from nagiosplugin.state import Ok, Warn, Critical


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

        cmd = '<show><system><disk-space><%2Fdisk-space><%2Fsystem><%2Fshow>'
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmd
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

        cmd = '<show><system><environmentals></environmentals></system></show>'
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmd
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


class Thermal(nagiosplugin.Resource):
    def __init__(self, host, token):
        self.host = host
        self.token = token

    def probe(self):
        """
        Meaning:    Will fetch the PA environmentals from the REST API
        Args:       Palo Alto as hostname or FQDN (required)
        """
        _log.info('reading thermal status from REST-API')

        cmd = '<show><system><environmentals><thermal></thermal></environmentals></system></show>'
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmd
        with urllib.request.urlopen(requestURL) as url:
            root = ET.parse(url).getroot()

        items = root.find('result')
        for item in items:
            items2 = item.findall('.//entry')
            for item2 in items2:
                temperature = item2.find('DegreesC').text
                maxt = item2.find('max').text
                desc = item2.find('description').text
                yield nagiosplugin.Metric(desc, float(temperature), min=0, max=float(maxt), context='temperature')

class ThermalSummary(nagiosplugin.Summary):
    def ok(self, results):
        text = ""
        for result in results:
            text += (str(result.metric) + ' Degrees, ')
        text = text[:-2]
        return text


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

        cmd = '%3Cshow%3E%3Csession%3E%3Cinfo%3E%3C%2Finfo%3E%3C%2Fsession%3E%3C%2Fshow%3E'

        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmd

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


class Certificate(nagiosplugin.Resource):
    def __init__(self, host, token, exclude, warning, critical):
        self.host = host
        self.token = token
        self.exclude = str(exclude).split(",")
        self.warning = int(warning)
        self.critical = int(critical)


    def probe(self):
        """
        Meaning:    Will fetch the maximum possible sessions, the number of current sessions and the throughput
                    from the REST API
        Args:       Palo Alto as hostname or FQDN (required)
        """
        _log.info('reading certificate information from REST-API')

        cmd = '<show><config><running><xpath>shared/certificate</xpath></running></config></show>'

        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmd

        with urllib.request.urlopen(requestURL) as url:
            root = ET.parse(url).getroot()

        certificates = root.findall('.//entry')

        for certificate in certificates:
            noGMT = certificate.find('not-valid-after').text.replace("GMT", "").strip()
            date_object = datetime.strptime(noGMT, '%b %d %H:%M:%S %Y')
            difference = date_object - datetime.today()
            try:
                status = certificate.find('status').text
            except AttributeError as e:
                status = ""
            if certificate.get('name') not in self.exclude:
                if status != "revoked":
                    if difference.days <= self.warning and difference.days >= self.critical:
                        yield nagiosplugin.Metric(certificate.get('name'), difference.days, context='certificates')

class CertificateContext(nagiosplugin.Context):
    def __init__(self, name, warning=None, critical=None, fmt_metric='{name} is {valueunit}', result_cls=Result):
        super(CertificateContext, self).__init__(name, fmt_metric, result_cls)
        self.warning = int(warning)
        self.critical = int(critical)

    def evaluate(self, metric, resource):
        if metric.value <= self.critical:
            return self.result_cls(Critical, None, metric)
        elif metric.value <= self.warning:
            return self.result_cls(nagiosplugin.state.Warn, None, metric)
        else:
            return self.result_cls(nagiosplugin.state.Ok, None, metric)


class CertificateSummary(nagiosplugin.Summary):
    def problem(self, results):
        list = []
        for result in results:
            list.append(str(result))
        output = ", ".join(list)
        return str(output)

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

        cmd = '<show><running><resource-monitor><minute><last>1<%2Flast>' \
                 '<%2Fminute><%2Fresource-monitor><%2Frunning><%2Fshow>'
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmd

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
    statefile = os.path.join(tempfile.gettempdir(), 'throughput')

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
            cmd = '<show><counter><interface>ethernet1/' + str(
                self.interface) + '</interface></counter></show>'
        elif self.prefix == 'tun':
            cmd = '<show><counter><interface>tunnel.' + str(self.interface) + '</interface></counter></show>'
        else:
            print('Unknown prefix!')
            sys.exit(3)
        requestURL = 'https://' + self.host + '/api/?key=' + self.token \
                     + '&type=op&cmd=' \
                     + cmd

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
    argp.add_argument('-E', '--exclude', default='',
                      help='Exclude certificates, separate certificate name by comma')
    argp.add_argument('-H', '--host', default='',
                      help='PaloAlto Host')
    argp.add_argument('-C', '--check', default='',
                      help='PaloAlto Check-Command. Available commands: '
                           'CPU, DiskSpace, SessInfo, Throughput, Environmental, Temperature, Certificates')
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
    elif args.check == 'Temperature':
        check = nagiosplugin.Check(
            Thermal(args.host, args.token),
            nagiosplugin.ScalarContext('temperature', args.warning, args.critical),
            ThermalSummary())
    elif args.check == 'Certificates':
        check = nagiosplugin.Check(
            Certificate(args.host, args.token, args.exclude, args.warning, args.critical),
            CertificateContext('certificates', args.warning, args.critical),
            CertificateSummary())
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
