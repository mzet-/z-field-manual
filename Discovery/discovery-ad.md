
# Discovery: Active Directory

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

### Reference

In-depth domain recon:

```
https://adsecurity.org/?p=2535
https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments?slide=96
```

Domain recon (from Windows box):

```
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
https://pentestlab.blog/2018/05/28/situational-awareness/
```

### Discovering AD name

### Sniffing for abusable protocols 

Broadcast/multicast protocols that could be abused (via poisoning/spoofing) by the attacker to impersonate as other nodes in the network:

```
NBT (NetBIOS over TCP/IP)
LLMNR
mDNS
DHCPv6
```

## OPSEC considerations

## Counter-countermeasures
