
# Discovery: Identifying Core Network Technologies

## Overview

MITRE ATT&CK mapping: N/A

## References

### Secure network architecture

```
Enterprise access model:
https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model

Zero-trust principles:
https://www.microsoft.com/security/blog/2021/01/19/using-zero-trust-principles-to-protect-against-sophisticated-attacks-like-solorigate/
https://beyondcorp.com/

Defense in depth principle:
https://risk-engineering.org/concept/defence-in-depth
https://www.fortinet.com/resources/cyberglossary/defense-in-depth
https://www.cisa.gov/uscert/bsi/articles/knowledge/principles/defense-in-depth
https://www.imperva.com/learn/application-security/defense-in-depth/

Example mitigations:
https://blog.scrt.ch/2020/12/28/state-of-pentesting-2020/
```

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
