
# Discovery: Identifying Core Network Technologies

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

Reference:

```
https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
```

LAN ARP scan to get an idea of network equipment's vendors (based on MAC):

```
nmap -n -sn -PR 192.168.0.0/24 | grep -E -v 'Host is up|Starting Nmap|Nmap done:' | while read -r ip; do read -r mac; echo -e "IP: $(cut -d' ' -f5 <<< $ip);\t $mac"; done
```

## OPSEC considerations

## Counter-countermeasures
