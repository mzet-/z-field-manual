
# Discovery: Services

## Overview

MITRE ATT&CK mapping: [T1046](https://attack.mitre.org/techniques/T1046/)

## Procedures

Objectives:

```
In:
hostsUp.txt - list of alive IPs discovered in tested IP space
allPorts.txt - ports seen opened in tested IP space

Out:
hostsUp-vscan.{nmap,gnmap,xml} - nmap's initial enumeration (`-A`) of all servies in scope
```

Initial vuln scan:

```
nmap -n -PN -sS -A --script=vulners --open -iL hostsUp.txt -p$(cat allPorts.txt | tr '\n' ',') -oA vscans/base-vscan -T4 --max-hostgroup 16
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
