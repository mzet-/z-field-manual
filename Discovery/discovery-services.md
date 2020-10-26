
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
mkdir vscan-1; cp hostsUp.txt vscan-1/; cp allPorts.txt vscan-1/;
nmap -n -PN -sS -A --script=vulners --open -iL vscan-1/hostsUp.txt -p$(cat vscan-1/allPorts.txt | tr '\n' ',') -oA vscan-1/base-vscan -T4 --max-hostgroup 24
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
