
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
screen
source ~/bin/hacking-helpers.inc
DIR_NAME="vscan-1"; mkdir $DIR_NAME; cp hostsUp.txt $DIR_NAME/; cp allPorts.txt $DIR_NAME/;
OR (with specific prefix):
prefix="net1"; DIR_NAME="vscan-1-$prefix"; mkdir $DIR_NAME; cp $prefix-hostsUp.txt $DIR_NAME/hostsUp.txt; cp $prefix-allPorts.txt $DIR_NAME/allPorts.txt

export DIR_NAME="vscan-1"; nmap -O --osscan-limit --traceroute -n -PN -sS -sV --script="(default or discovery or safe or vuln) and not (intrusive or broadcast-* or targets-*)" --open -iL $DIR_NAME/hostsUp.txt -p$(cat $DIR_NAME/allPorts.txt | tr '\n' ',')$(topNports 50 tcp 8000) -oA $DIR_NAME/base-vscan -T4 --max-hostgroup 24

# OR (much faster):

export DIR_NAME="vscan-1"; nmap -O --osscan-limit --traceroute -n -PN -sS -sV --script="(default or discovery or safe or vuln) and not (intrusive or broadcast-* or targets-* or http-* or ssl-*)" --open -iL $DIR_NAME/hostsUp.txt -p$(cat $DIR_NAME/allPorts.txt | tr '\n' ',')$(topNports 50 tcp 8000) -oA $DIR_NAME/base-vscan -T4 --max-hostgroup 24
```

Additional (incremental) scan after discovering new ports and/or hosts:

```
# Additional (incremental) scans after discovering new ports:
export DIR_NAME="vscan-2"; mkdir $DIR_NAME
PREV_SCAN_PORTS="vscan-1/allPorts.txt"; cp "$PREV_SCAN_PORTS" "$DIR_NAME"; grep -x -v -f "$PREV_SCAN_PORTS" allPorts.txt | tee $DIR_NAME/allPorts-delta.txt

# Additional (incremental) scans after discovering new hosts:
PREV_SCAN_HOSTS="vscan-1/hostsUp.txt"; cp "$PREV_SCAN_HOSTS" "$DIR_NAME"; grep -x -v -f "$PREV_SCAN_HOSTS" hostsUp.txt | tee $DIR_NAME/hostsUp-delta.txt
```

Service scanning:

```
screen
source ~/bin/hacking-helpers.inc

# Scan newly discovered ports on old number of hosts:
export DIR_NAME="vscan-2"; nmap -O --osscan-limit --traceroute -n -PN -sS -sV --script="(default or discovery or safe or vuln) and not (intrusive or broadcast-* or targets-* or http-* or ssl-*)" --open -iL $DIR_NAME/hostsUp.txt -p$(cat $DIR_NAME/allPorts-delta.txt | tr '\n' ',')$(topNports 50 tcp 8000) -oA $DIR_NAME/base-vscan-portsDelta -T4 --max-hostgroup 24

# Scan newly discovered hosts on all discovered ports:
export DIR_NAME="vscan-2"; nmap -O --osscan-limit --traceroute -n -PN -sS -sV --script="(default or discovery or safe or vuln) and not (intrusive or broadcast-* or targets-* or http-* or ssl-*)" --open -iL $DIR_NAME/hostsUp-delta.txt -p$(cat $DIR_NAME/allPorts.txt $DIR_NAME/allPorts-delta.txt | tr '\n' ',')$(topNports 50 tcp 8000) -oA $DIR_NAME/base-vscan-hostsDelta -T4 --max-hostgroup 24
```

Merge results (handy for Metasploit's `db_import`):

```
for i in $(ls vscans/*.xml); do echo -n "$i,"; done | head -c -1 |  xargs ./gnxmerge.py -s | tee vscans/vscanlatest-$(date +%F_%H-%M).xml
```

## OPSEC considerations

## Counter-countermeasures
