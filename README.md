## DNSBH

A basic DNS blackhole zone, and bind9 configuration creation
utility.  Will read a URL passed to it, and using a regular
expression, extracts domain names from the content, and
writes a bind9 named configuration file, and blackhole
zone file.

Also has the ability to allow the user to specify a TTL, and
IP destination to resolve traffic to.

Author: Joff Thyer
Black Hills Information Security
http://www.blackhillsinfosec.com/
http://www.securityweekly.com/


