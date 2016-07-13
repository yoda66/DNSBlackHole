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


def create_zonefile(content, bh_zonefile,
                    named_filename, bdir='', banner=''):
    # regular expression to match a domain name
    rxp = re.compile(
        r'\b(?P<domain>(?:[a-z0-9\-]+\.){1,}(?:[a-z0-9\-]+))\b'
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
        m = rxp.match(line, re.IGNORECASE)
        if m:
            recs += 1
            output = 'zone "%s" { type master; file "%s%s"; };\n' \
                % (m.group('domain'), bdir, bh_zonefile)
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
    args = parser.parse_args()

    print '[*] %s' % (banner)
    try:
        content = fetchurl(args.url)
        create_zonefile(
            content,
            args.bhzonefile,
            args.namedconf,
            args.bdir,
            banner=banner
        )
    except Exception as e:
        print '[-] %s' % (e)
        sys.exit(0)
