
# Discovery: passive

## Overview

MITRE ATT&CK mapping: [T1040](https://attack.mitre.org/techniques/T1040/)

[NSA/CSS Cyber Threat Framework](https://media.defense.gov/2019/Jul/16/2002158108/-1/-1/0/CTR_NSA-CSS-TECHNICAL-CYBER-THREAT-FRAMEWORK_V2.PDF) mapping: `Presence:Sniff network`

Atomic Red Team test: [T1040 - Network Sniffing](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.md)

## Procedures

Live sniffing in Wireshark via SSH:

```
ssh -o ProxyCommand="ssh -W %h:%p -i $HOME/ssh_key proxy_user@proxy_host" user@host "sudo /usr/sbin/tcpdump -i eth0 -U -s0 -w - '<FILTER> and not port 22'" | sudo wireshark -k -i -
```

Capturing traffic for later review:

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
cat /usr/share/responder/logs/Responder-Session.log | extractIPs | sort -u

# IPs seen by tcpdump:
tcpdump -nn -r <SESSION_FILE> -l | grep -o -E '[0-9]+(\.[0-9]+){3}' | sort -u

# with Nmap:
nmap -sL --script=targets-sniffer --script-args=newtargets,targets-sniffer.timeout=5s,targets-sniffer.iface=eth0

# verify if it is already in discovered hosts ('hostsUp.txt') file:
grep -v -f hostsUp.txt <(process returning IP list)
```

## OPSEC considerations

## Counter-countermeasures
