
# Discovery: scanning

MITRE ATT&CK: [T1018](https://attack.mitre.org/techniques/T1018/)

## Overview

MITRE ATT&CK mapping: [T1040](https://attack.mitre.org/techniques/T1040/)

Atomic Red Team test: [T1040 - Network Sniffing](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md)

## Procedures

Reference:

```
https://nmap.org/book/host-discovery.html
https://nmap.org/book/man-host-discovery.html
https://nmap.org/book/nping-man-briefoptions.html
```

Prereq:

 - [observer.sh](scripts/observer.sh)

Objectives:

```
In:
IP-ranges.txt - file with IPs in scope

Out:
hostsUp.txt - initial list of alive IPs discovered in tested scope
allPorts.txt - initial list of port numbers that were seen opened in tested scope
```

One-time host sweeps:

```
# ping (ICMP echo request) sweeps:
for i in $(seq 1 254); do ping -c1 192.168.1.$i | grep 'time=' | cut -d" " -f4 | cut -d":" -f1 & done
nmap -sn 192.168.1.1-254 -oG - -PE

# host discovey (default):
nmap -n -sn == ICMP echo request,
               TCP SYN to port 443,
               TCP ACK to port 80,
               ICMP timestamp request
nmap -n -sn -T4 -iL IP-ranges.txt
nmap -n -sn -T4 -iL IP-ranges.txt -oG - | grep -v Nmap | cut -d' ' -f2 | tee hostsUp.txt hostsPings.txt

# comprehensive (can be slow for huge networks) (could add: --source-port 53):
nmap -n -sn -T4 -PE -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -iL IP-ranges.txt
nmap -n -sn -T4 -PE -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -iL IP-ranges.txt -oG - | grep -v Nmap | cut -d' ' -f2 | tee hostsUp.txt hostsPings.txt
```

### Scanning: TCP

One-time, fast scan for detecting of first batch of alive hosts:

```
# initial scan:
nmap -n -PN -sS -iL IP-ranges.txt -T4 --open -F -oA pscans/all-fast-onetime

# alternative for larger networks:
nmap -n -PN -sS -iL IP-ranges.txt -T4 --open --top-ports 50 -oA pscans/all-fast-onetime

# store initial list of alive hosts and ports that have been observed as opened:
./gnxparse.py -p pscans/all-fast-onetime.xml | grep -v 'Port' > allPorts.txt
./gnxparse.py -ips pscans/all-fast-onetime.xml | grep -v 'IPv4' > hostsUp.txt
```

Long-run "scanning jobs" with frequent updates of results at `pscans/`:

```
# Continuous, randomized, full IP space, full port range scan jobs with small host groups (for frequent update of results): 
nmap -n -PN -sS -iL IP-ranges.txt -T4 --open -p- -oA pscans/all-full-rand-job-1 --randomize-hosts --max-hostgroup 4

# scan 'rawr' ports (where 'rawrPorts' is Bash function returning list of rawr ports):
nmap -n -Pn -sS --open -iL IP-ranges.txt -p$(rawrPorts) -oA pscans/all-rawrPN -T4 --max-hostgroup 16

# full scope - next top 3000 ports (in batches of 100 ports):
screen /bin/bash -c 'for i in $(seq 1 30); do masscan -iL IP-ranges.txt -p$(topNports 100 $((i*100))) --rate 1000 -oX pscans/masscan-offset$((i*100))-top100.xml; done'

# full port range scan of already discovered hosts:
nmap -n -sS --open -iL hostsUp.txt -p- -oA pscans/hostsUp-all -T4 --max-hostgroup 16
```

Periodical runs based on the (incremental) findings at `pscans/`:

```
# fetch newly discovered ports and hosts from 'pscans/':
./observer.sh pscans/

# full IP space scan of previously seen (and not yet 'horizontally' scanned) ports:
nmap -n -Pn -sS --open -iL IP-ranges.txt -p$(cat allPorts.txt | tr '\n' ',') -oA pscans/all-deltaPorts-$(date +%F_%H-%M) -T4
# OR (only specific delta):
nmap -n -Pn -sS --open -iL IP-ranges.txt -p$(cat vscans/delta-ports-* | tr '\n' ',') -oA pscans/all-deltaPorts-$(date +%F_%H-%M) -T4

# full port range scan of previously discovered (and not yet fully scanned) hosts:
nmap -n -sS --open -iL vscans/delta-hosts-* -p- -oA pscans/deltaHosts-all-$(date +%F_%H-%M) -T4'
```

### Scanning: UDP

Prereq:

```
https://raw.githubusercontent.com/portcullislabs/udp-proto-scanner/master/udp-proto-scanner.conf
https://raw.githubusercontent.com/portcullislabs/udp-proto-scanner/master/udp-proto-scanner.pl
```

Probing for popular UDP-based services:

```
ranges2IPs IP-ranges.txt > IP-list.txt
udp-proto-scanner.pl --file IP-list.txt | tee all-udp-proto-scanner.out
```

Nmap UDP scan:

    nmap -n -sU --top-ports 500 -PN --open --reason -T4 -iL IP-ranges.txt -oA udp-all-fast-pscan

### DNS queries

Reverse DNS:

```
nmap -R -sL -T4 -iL IP-ranges.txt | sort -k 5.1 | grep -o -E '\(.+\)' | extractIPs | tee -a hostsUp.txt
sort -u hostsUp.txt -o hostsUp.txt
```

DNS brute-force:

```
TODO
```

### Protocols-specific broadcasts/multicasts

```
# discovery of additional network devices via multicasting / broadcasting
nmap --script mrinfo -e ens160 -d
nmap -sU -p 5351 --script=nat-pmp-info 10.10.10.0/24 -d --open
nmap --script broadcast-pim-discovery -e ens160 -d --script-args 'broadcast-pim-discovery.timeout=15'
nmap --script='broadcast-eigrp-discovery,broadcast-igmp-discovery,broadcast-ospf2-discover' -e ens160 --script-args 'broadcast-igmp-discovery.version=all, broadcast-igmp-discovery.timeout=13' -d

TODO:
https://nmap.org/nsedoc/scripts/wsdd-discover.html
https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-echo.html
https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-invalid-dst.html
https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-mld.html
https://nmap.org/nsedoc/scripts/targets-ipv6-multicast-slaac.html
```

## OPSEC considerations

## Counter-countermeasures
