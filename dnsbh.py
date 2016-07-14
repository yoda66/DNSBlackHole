#!/usr/bin/env python

import argparse
import re
import urllib2
import sys
from datetime import datetime


def fetchurl(url):
    content = urllib2.urlopen(url).read()
    print '[*] Fetched %d bytes from %s' % (len(content), url)
    return content


def create_zone_file(bh_zonefile, ttl=3600, ip='127.0.0.1', banner=''):
    print '[*] Created zonefile [%s], TTL:%d, IP:%s' \
            % (bh_zonefile, ttl, ip)
    f = open(bh_zonefile, 'w')
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
""" % (banner, now, ttl, ip))
    f.close()
    return


def create_named_conf(content, bh_zonefile,
                    named_filename, bdir='', banner=''):
    # regular expression to match a domain name
    rxp = re.compile(
        r'.+?(?P<domain>(?:[a-z0-9\-]+\.){1,}(?:[a-z]+))',
        re.IGNORECASE
    )

    if bdir and bdir[-1] != '/':
        bdir += '/'

    f = open(named_filename, 'w')
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    f.write("""\
//
// %s
// Filename .......: %s
// Auto-Generated..: %s
//
""" % (banner, named_filename, now))

    recs = 0
    for line in content.split('\n'):
        if line and line[0] == '#':
            continue
        m = rxp.match(line)
        if m:
            recs += 1
            domain = m.group('domain').lower()
            output = 'zone "%s" { type master; file "%s%s"; };\n' \
                % (domain, bdir, bh_zonefile)
            f.write(output)
    print '[*] %d domains written to file: [%s]' % (recs, named_filename)
    f.close()
    return


if __name__ == '__main__':

    VERSION = '20160713'
    AUTHOR = 'Joff Thyer'
    banner = 'DNSBH Version %s, %s' % (VERSION, AUTHOR)
    parser = argparse.ArgumentParser(description=banner)
    parser.add_argument('url', help='malware domain list url')
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

    print '[*] %s' % (banner)
    try:
        content = fetchurl(args.url)
        create_zone_file(
            args.bhzonefile,
            ttl=args.ttl,
            ip=args.ip,
            banner=banner
        )
        create_named_conf(
            content,
            args.bhzonefile,
            args.namedconf,
            args.bdir,
            banner=banner
        )
    except Exception as e:
        print '[-] %s' % (e)
        sys.exit(0)
