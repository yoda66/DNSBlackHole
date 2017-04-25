#!/usr/bin/env python

import argparse
import re
import urllib2
import sys
from datetime import datetime


class DNSBH:

    # dict to hold unique domains
    DOMAINS = {}

    def __init__(self, url, zonefile='db.blackhole',
                 namedconf='named.bh.conf',
                 ttl=3600, ip='127.0.0.1', bdir='', banner=''):
        self.url = url
        self.zonefile = zonefile
        self.namedconf = namedconf
        self.ttl = ttl
        self.ip = ip
        self.banner = banner
        self.bdir = bdir
        if self.bdir and self.bdir[-1] != '/':
            self.bdir += '/'

        if not self.valid_ipv4_addr(self.ip):
            raise Exception('Invalid IP Address')
        self.content = self.fetchurl()
        self.create_zone_file()
        self.create_named_conf()
        return

    def valid_ipv4_addr(self, ip):
        """
        Returns true if an IPv4 address is valid
        """
        octet = r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
        rxp = re.compile(r'^((?:%s\.){3}(?:%s))$' % (octet, octet))
        m = rxp.match(ip)
        if m:
            return True
        return False

    def fetchurl(self):
        content = ''
        for u in self.url:
            try:
                content += urllib2.urlopen(u).read()
                print '[*] Fetched %d bytes from %s' % (len(content), u)
            except:
                continue
        return content

    def create_zone_file(self):
        """
        Creates a bind9 compatible zone file
        that redirects queries to the specified address
        """
        print '[*] Created zonefile [%s], TTL:%d, IP:%s' \
               % (self.zonefile, self.ttl, self.ip)
        f = open(self.zonefile, 'w')
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        f.write("""\
;
; %s
; Auto-generated: %s
;
$TTL %s
@ IN SOA localhost. root.localhost. (
          1     ; Serial
     604800     ; Refresh
      86400     ; Retry
    2419200     ; Expire
     604800 )   ; Negative Cache TTL
;
@   IN  NS  localhost.
@   IN  A   %s
*   IN  A   %s
""" % (self.banner, now, self.ttl, self.ip, self.ip))
        f.close()
        return


    def create_named_conf(self):
        """
        Creates a bind9 configuration file for all
        domains in the data passed into the function.
        """
        # regular expression to match a domain name
        rxp = re.compile(
            r'.+?(?P<domain>(?:[a-z0-9\-]+\.){1,}(?:[a-z]+))',
            re.IGNORECASE
        )

        f = open(self.namedconf, 'w')
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        f.write("""\
//
// %s
// Filename .......: %s
// Auto-Generated..: %s
//
""" % (self.banner, self.namedconf, now))

        for line in self.content.split('\n'):
            if line and line[0] == '#':
                continue
            m = rxp.match(line)
            if m:
                domain = m.group('domain').lower()
                self.DOMAINS[domain] = 1

        # write to file
        for domain in sorted(self.DOMAINS.keys()):
                output = 'zone "%s" { type master; file "%s%s"; };\n' \
                          % (domain, self.bdir, self.zonefile)
                f.write(output)
        recs = len(self.DOMAINS)
        print '[*] %d domains written to file: [%s]' % (recs, self.namedconf)
        f.close()
        return


if __name__ == '__main__':

    VERSION = '20160713'
    AUTHOR = 'Joff Thyer'
    banner = 'DNSBH Version %s, %s' % (VERSION, AUTHOR)
    parser = argparse.ArgumentParser(description=banner)
    parser.add_argument('url', nargs='+', help='malware domain list urls')
    parser.add_argument(
        '-b', '--bhzonefile',
        default='db.blackhole'
    )
    parser.add_argument(
        '-n', '--namedconf',
        default='named.bh.conf'
    )
    parser.add_argument(
        '-d', '--bdir', dest='bdir',
        default=''
    )
    parser.add_argument(
        '-i', '--ip', dest='ip',
        default='127.0.0.1'
    )
    parser.add_argument('--ttl', type=int, default=3600)
    args = parser.parse_args()

    try:
        DNSBH(
            args.url,
            zonefile=args.bhzonefile,
            namedconf=args.namedconf,
            bdir=args.bdir,
            ttl=args.ttl,
            ip=args.ip,
            banner=banner
        )
    except Exception as e:
        print '[-] %s' % (e)
        sys.exit(0)
