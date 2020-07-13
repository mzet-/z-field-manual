
# Discovery: passive

## Overview

MITRE ATT&CK mapping: [T1040](https://attack.mitre.org/techniques/T1040/)

Atomic Red Team test: [T1040 - Network Sniffing](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md)

## Procedures

Sniffing:

```
# {broad,multi}cast traffic excluding ARP:
tcpdump -nn -i eth0 -w tcpdump-b-m-no-arp.pcap ether broadcast and ether multicast and not arp

# Sniffs the network for incoming broadcast communication and attempts to decode the received packets.
# https://nmap.org/nsedoc/scripts/broadcast-listener.html
nmap --script broadcast-listener -e eth0 --script-args=broadcast-listener.timeout=30

# Overview of IPv4 traffic:
tcpdump -i eth0 -w session1-all-ipv4.pcap -nn not ip6 and not port 22
# Full packet capture of IPv4 traffic:
tcpdump -X -s0 -i eth0 -w session1-all-ipv4-full-content.pcap -nn not ip6 and not port 22

# Overview of IPv6 traffic:
tcpdump -i eth0 -w session1-all-ipv6.pcap -nn ip6
# Full packet capture of IPv6 traffic:
tcpdump -i eth0 -w session1-all-ipv6-full-content.pcap -nn ip6
```

OS fingerprinting:

```
# Linux
responder -I eth0 -A -f

# Windows
Invoke-Inveigh -IP <current-box-ip> -ConsoleOutput Y -Inspect Y

TODO:
p0f
```

Discovery of 'hidden' (i.e. all ports filtered, no ping replies) hosts:

```
# IPs seen be responder:
cut -d' ' -f9 Responder/logs/Analyzer-Session.log | sort -u
cut -d' ' -f12 Responder/logs/Responder-Session.log | sort -u

# IPs seen by tcpdump:
tcpdump -nn -r <SESSION_FILE> -l | grep -o -E '[0-9]+(\.[0-9]+){3}' | sort -u

# verify if it is already in discovered hosts ('hostsUp.txt') file:
grep -v -f hostsUp.txt <(process returning IP list)
```

## OPSEC considerations

## Counter-countermeasures
