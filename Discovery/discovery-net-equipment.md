
# Discovery: Identifying Network Equipment

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

### Generic probes

Trickery to extract from Nmap's `--traceroute` only routers (i.e. network nodes that decremented TTL):

```
nmap -n -T4 -PN -sn --traceroute -iL hostsPings.txt -oX netTopologyICMP.xml --script targets-traceroute --script-args newtargets
nmap --script targets-xml --script-args newtargets,iX=netTopologyICMP.xml -n -sL -oG - | grep -v Nmap | cut -d' ' -f2 > /tmp/withRouters.txt
grep -v -f hostsPings.txt /tmp/withRouters.txt > routerIPs.txt
```

Look for protocols and indicators typical for network devices:

```
# looking for telnet, SNMP, TFTP, Cisco 'SIET' port (4786)
nmap -n -Pn -sS -sU -pT:23,69,4786,4001,U:161,162 -iL IP-ranges.txt -T4 --open -oG network-devices.out
cat network-devices.out | grep -v '161/open|filtered/udp//snmp///' | grep -v '162/open|filtered/udp//snmptrap///' | grep -v 'Status: Up' > network-devices.txt

# look for SSH daemons with router/swich related banners
nmap -n -Pn -sS -T4 -p22 -iL scope.txt -oG - --open -sV --version-intensity 0 | grep -v 'Status: Up' | tee ssh-banners.out

# grep for strings: 
'cisco|OpenSSH 12.1'
```

Look for network devices web panels:

```
# (after masscan, only ports 80)
screen -d -m /bin/bash -c $'for i in $(cat masscan-allPorts.min | grep \':80$\'); do echo "$i:"; timeout 7s curl -s -L -k -I "http://$i"; done | tee http-headers.out'

# (from IP list, only port 80)
while read i; do timeout 2s curl -s -w "%{remote_ip}" -L -I "http://$i" & done < hosts-fastTcp.txt > http-headers.out
while read i; do timeout 2s curl -s -w "%{remote_ip}" -L -k -I "https://$i" & done < hosts-fastTcp.txt > https-headers.out
screen /bin/bash -c 'while read i; do timeout 2s curl -s -w "%{remote_ip}" -L -k -I "https://$i" & done < hosts-fastTcp.txt > https-headers.out'

# (BEST: wth URLS list already generated)
screen -d -m /bin/bash -c 'while read i; do echo "$i:"; timeout 7s curl -s -L -k -I "$i"; done < urls.txt | tee http-headers.out'
then grep for:
'level_15_access|ios|cisco|level_15_or_view_access|level_1_or_view_access'
```

TODO:

```
http://vulnerabilityassessment.co.uk/Penetration%20Test.html
find: Cisco Specific Testing

https://gitlab.com/kalilinux/packages/cisco-global-exploiter/raw/kali/master/cge.pl

https://gitlab.com/kalilinux/packages/cisco-auditing-tool/tree/kali/master

http://www.vulnerabilityassessment.co.uk/cisco.htm
```

### MikroTik specific probes

Example hardware:

    https://mikrotik.com/product/RB3011UiAS-RM
    Architecture: ARM

Operating System: `RouterOS`

    Arch: i386 based on Linux v3.3.5 kernel
    https://wiki.mikrotik.com/wiki/Manual:RouterOS_features
    https://wiki.mikrotik.com/wiki/Manual:Upgrading_RouterOS#Version_numbering
    https://mikrotik.com/download/changelogs

Possible Attack Surface: **TCP 8291 port**

Management port (used by MikroTik's Winbox GUI desktop application).

Possible Attack Surface: **TCP 8728 port**

RouterOS API protocol.

    https://wiki.mikrotik.com/wiki/Manual:API
    https://nmap.org/nsedoc/scripts/mikrotik-routeros-brute.html

Possible Attack Surface: **UDP 5678 port**

MikroTik Neighbor Discovery Protocol (MNDP).

    https://raw.githubusercontent.com/nmap/nmap/a035e8e2f7b058a2cc45bc4d42aeb56e2186696f/scripts/broadcast-mndp-discover.nse

Noteworthy vulnerabilities:

    https://www.tenable.com/security/research/tra-2019-07

## OPSEC considerations

## Counter-countermeasures
