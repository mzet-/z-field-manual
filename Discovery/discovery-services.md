
# Discovery: Services

## Overview

MITRE ATT&CK mapping: [T1046](https://attack.mitre.org/techniques/T1046/)

## Procedures

Objectives:

```
In:
hostsUp.txt - list of alive IPs discovered in tested IP space to the date
allPorts.txt - ports seen opened in tested IP space to the date

Out:
vscan-1/base-vscan.{nmap,gnmap,xml} - nmap's initial enumeration (`-A`) of all services in scope to the date
```

Vuln scan snapshot:

```
DIR_NAME="vscan-1"; mkdir $DIR_NAME; cp hostsUp.txt $DIR_NAME/; cp allPorts.txt $DIR_NAME/;
DIR_NAME="vscan-1" nmap --traceroute -n -PN -sS -sV --script="(default or discovery or safe or vuln) and not (intrusive or broadcast-* or targets-*)" --open -iL $DIR_NAME/hostsUp.txt -p$(cat $DIR_NAME/allPorts.txt | tr '\n' ',') -oA $DIR_NAME/base-vscan -T4 --max-hostgroup 24
# OR (much faster):
DIR_NAME="vscan-1" nmap --traceroute -n -PN -sS -sV --script="(default or discovery or safe or vuln) and not (intrusive or broadcast-* or targets-* or http-* or ssl-*)" --open -iL $DIR_NAME/hostsUp.txt -p$(cat $DIR_NAME/allPorts.txt | tr '\n' ',') -oA $DIR_NAME/base-vscan -T4 --max-hostgroup 24
```

Additional scans after discovering new hosts:

```
nmap -n -PN -sS -A --script=vulners --open -iL vscans/delta-hosts-* -p$(cat allPorts.txt | tr '\n' ',') -oA vscans/base-delta-hosts-$(date +%F_%H-%M) -T4
```

Additional scans after discovering new ports:

```
nmap -n -Pn -sUS -A --script=vulners --open -iL IP-ranges.txt -p$(cat vscans/delta-ports-* | tr '\n' ',') -oA vscans/base-delta-ports-$(date +%F_%H-%M) -T4
```

Merge results:

```
for i in $(ls vscans/*.xml); do echo -n "$i,"; done | head -c -1 |  xargs ./gnxmerge.py -s | tee vscans/vscanlatest-$(date +%F_%H-%M).xml
```

## OPSEC considerations

## Counter-countermeasures
