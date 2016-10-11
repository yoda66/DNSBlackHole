#!/usr/bin/env python

import sys
import os
import re
import math
import urllib2
import socket
import struct
from datetime import datetime, timedelta
from optparse import OptionParser

"""
DNS Cache and Log Analyser
Author: Joff Thyer (c) 2016
Black Hills Information Security

Analyzes DNS logging information from Windows
Domain Controller

"""


class DNS_File_Analyzer:

    def __init__(self, dirname, detail=False, net=None):
        self.dnstypes = [
            'A', 'NS', 'CNAME', 'SOA', 'MINFO', 'MX',
            'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT',
            'NSAP', 'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS',
            'AAAA', 'LOC', 'EID', 'NIMLOC', 'SRV', 'ATMA',
            'NAPTR', 'KX', 'CERT', 'DNAME', 'SINK', 'OPT',
            'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC',
            'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA',
            'HIP', 'NINFO', 'RKEY', 'TALINK', 'CDS', 'CDNSKEY',
            'OPENPGPKEY', 'SPF', 'UINFO', 'UID', 'GID', 'TKEY',
            'TSIG', 'IXFR', 'AXFR', 'MAILA', 'MAILB', 'URI',
            'CA', 'TA', 'DLV', 'PTR', 'ZERO', 'ANY', 'ALL'
        ]
        self.dnsrcodes = [
            'NOERROR', 'SERVFAIL', 'FORMERR', 'NOTIMPL', 'REFUSED',
            'NXDOMAIN', 'YXDOMAIN', 'NXRRSET', 'YXRRSET',
            'NOTAUTH', 'NOTZONE',
            'BADVERS', 'BADSIG', 'BADKEY', 'BADTIME',
            'BADMODE', 'BADNAME', 'BADALG', 'BADTRUNC'
        ]

        self.dirname = dirname
        self.stats = {}
        self.detail = detail
        self.freq_rcode_types = {}
        self.freq_query_types = {'QU': {}, 'AN': {}}
        self.sum_rectypes = {'RC': {}, 'QU': {}, 'AN': {}}
        self.extstats = {'RC': {}, 'QU': {}, 'AN': {}}
        self.net = net
        self.DNS = {}
        self.DNSCache = {}
        self.BAD_DOMAIN = []
        self.file_cache = []
        self.dnslogfile = {}
        self.re_domain = r'(?P<dom>@|([a-zA-Z-_0-9]+\.){1,}[a-zA-Z-_0-9]+)'

        self.datetime_begin = None
        self.datetime_end = None

        ot = '(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])'
        re_network = r'^%s\.%s\.%s\.%s/[1-3]{0,1}\d{1}$' % \
            (ot, ot, ot, ot)
        if net and not re.match(re_network, net):
            raise Exception('Invalid network address specified')

        try:
            self.lootdir = '%s/.dns_cache_analyzer' % \
                (os.path.expanduser('~'))
            if not os.path.isdir(self.lootdir):
                os.mkdir(self.lootdir)
        except:
            raise

        # initialize qtype dictionaries
        for qt in self.dnstypes:
            self.sum_rectypes['QU'][qt] = 0
            self.sum_rectypes['AN'][qt] = 0
            self.extstats['QU'][qt] = {}
            self.extstats['AN'][qt] = {}
        for rc in self.dnsrcodes:
            self.sum_rectypes['RC'][rc] = 0
            self.extstats['RC'][rc] = {}

    def run(self):
        self.dshield()
        self.process_dir()
        #self.process_dns_cache()
        self.process_dns_logs()
        self.print_results()
        self.print_stddev_warnings()

    def _in_localnet(self, ip):
        if self.net is None:
            return True
        network, cidr = self.net.split('/')
        cidr = int(cidr)
        mask = socket.inet_ntoa(
            struct.pack(
                ">I", (0xffffffff << (32 - cidr))
                & 0xffffffff
            )
        )
        b_ip = struct.unpack('!L', socket.inet_aton(ip))[0]
        b_network = struct.unpack('!L', socket.inet_aton(network))[0]
        b_mask = struct.unpack('!L', socket.inet_aton(mask))[0]
        b_broadcast = (b_network | ~b_mask) & 0xffffffff
        if b_ip >= b_network and b_ip <= b_broadcast:
            return True
        return False

    def _fix_rr(self, domain):
        temp = []
        re1 = r'\(\d+\)([a-z0-9_\-]+)'
        rxp1 = re.compile(re1)
        for r in rxp1.findall(domain):
            temp.append(r)
        return ".".join(temp)

    def process_dir(self):
        if not os.path.exists(self.dirname):
            raise Exception('directory [%s] does not exist' % (self.dirname))

        rxp_bind = re.compile(
            r'^(.+(\r\n){0,})^.+client\s(\d{1,3}\.){3}\d{1,3}#\d{1,5}',
            re.M
        )
        for f in os.listdir(self.dirname):
            if os.path.isdir(f):
                continue
            filename = '%s/%s' % (self.dirname, f)
            try:
                f = open(filename, 'r')
                header = f.read(512)
                f.close()
                if re.match(r'^DNS Server log', header):
                    self.dnslogfile[filename] = { 'type': 'microsoft' }
                elif rxp_bind.match(header):
                    
                    self.dnslogfile[filename] = { 'type': 'bind9' }
                elif re.match(r'(\r\n;){2}\s+Zone:\s+\.\.cache', header, re.M):
                    self.file_cache.append(filename)
            except Exception as e:
                print '[*] Warning: %s' % (e)

    def process_dns_logs(self):
        for f in self.dnslogfile:
            sys.stderr.write('\r[*] Processing: %s\x1b[K ' % (f))
            if self.dnslogfile[f]['type'] == 'microsoft':
                self.read_ms_dns_log(f)
            elif self.dnslogfile[f]['type'] == 'bind9':
                self.read_bind_dns_log(f)

        sys.stderr.write('\r\n[*] Processing all results')
        for r in self.DNS:
            id, ipaddr, xid, qr = r.split(':')

            rcode = self.DNS[r]['rcode']
            qtype = self.DNS[r]['qtype']

            # warn if bad domain
            if self.DNS[r]['rr'] in self.BAD_DOMAIN:
                print '[*] WARNING: Suspicious domain [%s]' % \
                    (self.DNS[r]['rr'])

            # summary stats
            if qtype not in self.freq_query_types[qr].keys():
                self.freq_query_types[qr][qtype] = 1
            else:
                self.freq_query_types[qr][qtype] += 1

            # response codes
            if rcode not in self.freq_rcode_types.keys():
                self.freq_rcode_types[rcode] = 1
            else:
                self.freq_rcode_types[rcode] += 1

            # tally totals, and response codes
            if ipaddr not in self.stats.keys():
                self.sum_rectypes['RC'][rcode] += 1
                self.stats[ipaddr] = {
                    'TOTAL': 1,
                    'RC': {rcode: 1},
                    'QU': {}, 'AN': {}
                }
            else:
                self.stats[ipaddr]['TOTAL'] += 1
                if rcode not in self.stats[ipaddr]['RC']:
                    self.stats[ipaddr]['RC'][rcode] = 1
                    self.sum_rectypes['RC'][rcode] += 1
                else:
                    self.stats[ipaddr]['RC'][rcode] += 1

            # tally query types
            if qtype not in self.stats[ipaddr][qr]:
                self.stats[ipaddr][qr][qtype] = 1
                self.sum_rectypes[qr][qtype] += 1
            else:
                self.stats[ipaddr][qr][qtype] += 1

    def standard_deviation(self, mean, type, code):
        n = 0
        diff_sqsum = 0
        for rec in self.stats:
            if code not in self.stats[rec][type]:
                continue
            diff = float(self.stats[rec][type][code]) - mean
            diff_sqsum += (diff * diff)
            n += 1
        variance = diff_sqsum / n
        return math.sqrt(variance)

    def print_stddev_warnings(self):
        global ANSI
        out = {}
        for rec in self.stats:
            for code in ['RC', 'QU', 'AN']:
                for r in self.stats[rec][code]:
                    diff = math.fabs(self.stats[rec][code][r]) \
                        - self.extstats[code][r]['mean']
                    if diff > (2 * self.extstats[code][r]['stddev']):
                        if rec not in out.keys():
                            out[rec] = ['%s/%s' % (code, r)]
                        else:
                            out[rec].append('%s/%s' % (code, r))

        if out:
            print """\r
\r
\r
[+] **********************************************************\r
[+] *               +----------------------+                 *\r
[+] *               | STATISTICAL WARNINGS |                 *\r
[+] *               +----------------------+                 *\r
[+] * The following hosts performing DNS queries have total  *\r
[+] * statistics recorded on specific query types that are   *\r
[+] * more than 2 standard deviations away from the average  *\r
[+] * of all of the statistics in the specific category      *\r
[+] * These are considered SUSPICIOUS and will be shown in   *\r
[+] * a RED color below.                                     *\r
[+] **********************************************************\r
\r"""
            for t in out:
                print self.format_record(t, typecode=out[t])

    def search_typecode(self, typecode, type, code):
        if typecode is None:
            return False
        for r in typecode:
            h_type, h_code = r.split('/')
            if type == h_type and code == h_code:
                return True
        return False

    def format_record(self, key, typecode=None):
        global ANSI
        indent = '    [+] '
        dashes = '-' * 22

        out = '[*] %s%s%s\r\n' % (ANSI['bold'], key, ANSI['reset'])
        out += '%s%s\r\n' % (indent, dashes)

        for code in self.stats[key]['RC']:
            if self.search_typecode(typecode, 'RC', code):
                ansi1 = '%s%s' % (ANSI['bold'], ANSI['red'])
                ansi2 = ' * >2 StdDev *%s' % ANSI['reset']
            else:
                ansi1 = ansi2 = ''

            out += '%s%s%14s: %6d%s\r\n' % \
                (
                    ansi1,
                    indent, code,
                    self.stats[key]['RC'][code],
                    ansi2
                )

        out += '%s%s\r\n' % (indent, dashes)
        out += '%s%14s: %6d\r\n' % \
               (indent, 'TOTAL', self.stats[key]['TOTAL'])
        out += '%s%s\r\n' % (indent, dashes)

        out += '%sQuery Types ..........\r\n' % (indent)
        for qt in self.stats[key]['QU']:
            if self.search_typecode(typecode, 'QU', qt):
                ansi1 = '%s%s' % (ANSI['bold'], ANSI['red'])
                ansi2 = ' * >2 StdDev *%s' % ANSI['reset']
            else:
                ansi1 = ansi2 = ''

            out += '%s%s      [%6s]: %6d%s\r\n' % \
                   (
                        ansi1, indent, qt,
                        self.stats[key]['QU'][qt],
                        ansi2
                    )

        resptypes = '%sResponse Types .......\r\n' % (indent)
        for qt in self.stats[key]['AN']:
            if self.search_typecode(typecode, 'AN', qt):
                ansi1 = '%s%s' % (ANSI['bold'], ANSI['red'])
                ansi2 = ' * >2 StdDev *%s' % ANSI['reset']
            else:
                ansi1 = ansi2 = ''

            resptypes += '%s%s      [%6s]: %6d%s\r\n' % \
                (
                    ansi1, indent, qt,
                    self.stats[key]['AN'][qt],
                    ansi2
                )
        if len(resptypes) > 40:
            out += resptypes

        out += '%s%s\r\n' % (indent, dashes)
        out += '\r\n'
        return out

    def print_results(self):
        timediff = self.datetime_end - self.datetime_begin
        print """\r\n\r\n\r\n
[+] **************************\r
[+] *  DNS Analysis Results  *\r
[+] **************************\r
[+]\r
[+] Earliest DNS Log Timestamp...: %s\r
[+] Latest DNS Log Timestamp.....: %s\r
[+] Period of DNS Log Analysis...: %s\r
[+]\r\n""" % (self.datetime_begin, self.datetime_end, timediff)
        grand_total = 0
        out = ''
        for r in self.stats:
            grand_total += self.stats[r]['TOTAL']
            if self.detail:
                out = self.format_record(r)
                sys.stdout.write(out)

        #if self.detail:
        #    sys.stdout.write(out)

        # summary stats
        sys.stdout.write("""\r
[+] Response Code Totals\r
[+] -------------------\r
""")
        for r in self.freq_rcode_types:
            mean = self.freq_rcode_types[r] / \
                float(self.sum_rectypes['RC'][r])
            stddev = self.standard_deviation(mean, 'RC', r)
            self.extstats['RC'][r]['mean'] = mean
            self.extstats['RC'][r]['stddev'] = stddev
            sys.stdout.write(
                '[+] %10s: %6d (mean = %8.2f, stddev = %8.2f)\r\n' %
                (
                    r,
                    self.freq_rcode_types[r],
                    mean,
                    stddev
                )
            )

        for q in self.freq_query_types:
            sys.stdout.write("""\r
[+] Query Type Totals (%s)\r
[+] -----------------------\r
""" % (q))
            for r in self.freq_query_types[q]:
                mean = self.freq_query_types[q][r] / \
                    float(self.sum_rectypes[q][r])
                stddev = self.standard_deviation(mean, q, r)
                self.extstats[q][r]['mean'] = mean
                self.extstats[q][r]['stddev'] = stddev
                sys.stdout.write(
                    '[+] %10s: %6d (mean = %8.2f, stddev = %8.2f)\r\n' %
                    (
                        r, self.freq_query_types[q][r],
                        mean,
                        stddev
                    )
                )

        summary = """\r
[+] %6d unique IP addresses seen.\r
[+] %6d total DNS log entries processed.\r
""" % (len(self.stats), grand_total)
        sys.stdout.write(summary)

    def read_bind_dns_log(self, logfile):
        re_ip = '(\d{1,3}\.){3}\d{1,3}'
        re_domain = '(.+\.){1,}.+'
        re_timestamp = '(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})'
        re_client = '(?P<srcip>%s)#(?P<srcport>\d{1,5})' % (re_ip)
        re_postfix = '(?P<rr>%s)\sIN\s(?P<qtype>[A-Z]+)\s(?P<flags>(\+|\+[A-Z]+))' % (re_domain)
        re_serverip = '(?P<server>\(%s\))' % (re_ip)
        rxp = re.compile(
            r'^%s.+named.+:\sclient\s%s.+\squery:\s%s\s%s' %
            (
                re_timestamp, re_client,
                re_postfix, re_serverip
            )
        )

        # read file all in one chunk
        f = open(logfile, 'r')
        counter = 0
        errs = 0
        for line in f:
            m = rxp.match(line)
            if not m:
                errs += 1
                continue

            if not counter % 100000:
                sys.stderr.write('.')
                sys.stderr.flush()

            timestamp = datetime.strptime(
                m.group('timestamp'),
                '%Y-%m-%d %H:%M:%S.%f'
            )
            if self.datetime_begin is None:
                self.datetime_begin = timestamp
                self.datetime_end = timestamp
            else:
                if timestamp < self.datetime_begin:
                    self.datetime_begin = timestamp
                if timestamp > self.datetime_end:
                    self.datetime_end = timestamp

            key = '%06dd:%s:%s:QU' % \
                (counter, m.group('srcip'), counter)

            self.DNS[key] = {
                'flags.ascii': m.group('flags'),
                'qtype': m.group('qtype'),
                'rcode': 'NOERROR',
                'rr': m.group('rr')
            }
            counter += 1
        f.close()
    
    def read_ms_dns_log(self, logfile):
        f = open(logfile, 'r')
        data = f.read()
        f.close()

        re_timestamp = '^(?P<timestamp>\d{1,2}/\d{1,2}/\d{4} ' + \
                       '\d{1,2}:\d{1,2}:\d{1,2} (AM|PM))'
        re_postfix = '\s[A-F0-9]{4}\sPACKET\s+[A-F0-9]{16}\s(?P<postfix>.+)'
        re_all = r'%s%s' % (re_timestamp, re_postfix)
        rxp1 = re.compile(re_all)

        counter = 0
        for line in data.split('\n'):
            # if no datestamp at start of line
            m = rxp1.match(line)
            if not m:
                continue

            timestamp = datetime.strptime(
                m.group('timestamp'),
                '%m/%d/%Y %H:%M:%S %p'
            )
            if self.datetime_begin is None:
                self.datetime_begin = timestamp
                self.datetime_end = timestamp
            else:
                if timestamp < self.datetime_begin:
                    self.datetime_begin = timestamp
                if timestamp > self.datetime_end:
                    self.datetime_end = timestamp
        
            pf = m.group('postfix')
            proto = pf[0:3].lower()
            txrx = pf[4:7].lower()
            ipaddr = pf[8:23].strip()

            # is this address in my local network?
            if not self._in_localnet(ipaddr):
                continue

            xid = pf[24:28]
            qr = pf[29]
            if qr == ' ':
                qr = 'QU'
            elif qr == 'R':
                qr = 'AN'
            opcode = pf[31]
            flags_hex = pf[34:38]
            flags_ascii = pf[39:43].strip()
            rcode = pf[44:52].strip()
            qtype = pf[54:60].strip()
            rr = pf[61:-1]
            rr = self._fix_rr(rr)

            key = '%06d:%s:%s:%s' % (counter, ipaddr, xid, qr)
            counter += 1

            self.DNS[key] = {
                'proto': proto, 'txrx': txrx,
                'opcode': opcode,
                'flags.hex': flags_hex,
                'flags.ascii': flags_ascii,
                'rcode': rcode,
                'qtype': qtype,
                'rr': rr
            }

    def process_dns_cache(self):
        for f in self.file_cache:
            sys.stderr.write('\r[*] Processing: %s\x1b[K' % (f))
            self.read_cache_file(f)
            self.analyze_cache()

    def read_cache_file(self, filename):
        try:
            f = open(filename, 'r')
            data = f.read()
            f.close()
        except:
            raise

        re_type = r'?P<type>[A-Z]{1,}'
        re_ttl = r'?P<ttl>\d{1,5}'
        re_rr = r'?P<rr>[A-Za-z0-9:\._\-]+'

        re1 = re.compile(r'^;\s+Time:\s+([\w ]{8}[\d: ]{16}\s\w{3})')
        re2 = re.compile(r'^;\s+Server:\s+(%s)' % (self.re_domain))
        re3 = re.compile(
            r'^(%s)\s+(%s)\s+(%s)\s+(%s)' %
            (self.re_domain, re_ttl, re_type, re_rr)
        )
        re4 = re.compile(
            r'^\s{2,}(%s)\s+(%s)\s+(%s)' %
            (re_ttl, re_type, re_rr)
        )
        domain = ''
        for line in data.split('\n'):
            m1 = re1.match(line)
            m2 = re2.match(line)
            m3 = re3.match(line)
            m4 = re4.match(line)
            if m1:
                zone_time = m1.group(1)
            elif m2:
                zone_server = m2.group(1)
            elif m3:
                domain = m3.group('dom')
                ttl = m3.group('ttl')
                type = m3.group('type')
                rr = m3.group('rr')
                self.DNSCache[domain] = {
                    'rrset': [
                        {'ttl': ttl, 'type': type, 'rr': rr}
                    ]
                }
            elif m4:
                ttl = m4.group('ttl')
                type = m4.group('type')
                rr = m4.group('rr')
                self.DNSCache[domain]['rrset'].append(
                    {'ttl': ttl, 'type': type, 'rr': rr}
                )
            elif line and (line[0] == '\r' or line[0] == '\n'):
                continue

    def print_rr(self, r, rr, msg=None):
        global ANSI
        sys.stdout.write(
            '%-20s %4s IN %5s %-20s [%s%s%s]\r\n' %
            (
                r,
                rr['ttl'],
                rr['type'],
                rr['rr'],
                ANSI['red'], msg, ANSI['reset']
            )
        )

    def dshield(self, url=
                'https://isc.sans.edu/feeds/suspiciousdomains_Low.txt'):
        filename = '%s/%s' % (self.lootdir, os.path.basename(url))
        if os.path.exists(filename):
            ctime = os.stat(filename)[-1]
            delta = datetime.now() - datetime.fromtimestamp(ctime)
        else:
            delta = timedelta(hours=25)

        if delta < timedelta(hours=24):
            sys.stderr.write('[*] Fetching cached file %s\r\n' % (filename))
            try:
                f = open(filename, 'r')
                data = f.read()
                f.close()
            except:
                raise
        else:
            sys.stderr.write('[*] Fetching URL %s\r\n' % (url))
            req = urllib2.Request(url=url)
            f = urllib2.urlopen(req)
            data = f.read()
            try:
                f = open(filename, 'w')
                f.write(data)
                f.close()
            except:
                raise

        for line in data.split('\n'):
            if re.match(self.re_domain, line):
                self.BAD_DOMAIN.append(line)

    def analyze_cache(self):
        for r in self.DNSCache:
            if r == '@':
                continue
            for rr in self.DNSCache[r]['rrset']:
                if r in self.BAD_DOMAIN:
                    self.print_rr(r, rr, msg='suspicious domain')


if __name__ == '__main__':
    # terminal ANSI color codes
    ANSI = {
        'reset': '\x1b[0m',
        'bold': '\x1b[1m',
        'red': '\x1b[31m'
    }

    parser = OptionParser()
    parser.add_option(
        '--dir',
        help='specify directory containing files to analyze'
    )
    parser.add_option(
        '--net',
        help='specify network addresses to match for dns logging'
    )
    parser.add_option(
        '--detail',
        action='store_true', default=False,
        help='show detailed DNS client record summations'
    )
    (options, args) = parser.parse_args()
    print """\r
[*] --------------------------------\r
[*] DNS Cache and Log File Analyzer\r
[*] Version 1.1, Joff Thyer (c) 2016\r
[*] Black Hills Information Security\r
[*] --------------------------------\r
\r"""
    if not options.dir:
        parser.print_help()
        sys.exit(1)

    da = DNS_File_Analyzer(
        options.dir,
        detail=options.detail,
        net=options.net
    )
    da.run()
