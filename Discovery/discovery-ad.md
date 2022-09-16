
# Discovery: Active Directory

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

### Reference

In-depth domain recon:

```
https://book.hacktricks.xyz/windows-hardening/ntlm
https://book.hacktricks.xyz/windows/active-directory-methodology
https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments?slide=96
```

Domain recon (from Windows box):

```
https://adsecurity.org/?p=2535
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
https://pentestlab.blog/2018/05/28/situational-awareness/
```

Kerberos attacks:

```
https://www.tarlogic.com/blog/how-kerberos-works/
```

### Discovering AD name

Passively listen for DHCP broadcasts:

   tcpdump -i eth0 port 67 or port 68 -e -X

Broadcasting DHCP/DHCPv6 request:

   nmap --script broadcast-dhcp-discover -d
   nmap -6 --script broadcast-dhcp6-discover 

### Sniffing for abusable protocols 

Broadcast/multicast protocols that could be abused (via poisoning/spoofing) by the attacker to impersonate as other nodes in the network:

```
NBT (NetBIOS over TCP/IP)
LLMNR
mDNS
DHCPv6
SSDP
```

NBT (NetBIOS over TCP/IP):

    tcpdump -i eth0 udp port 137

LLMNR:

    socat -u UDP4-RECV:5355,ip-add-membership=224.0.0.252:eth0 /dev/null &
    tcpdump -i eth0 udp port 5355

mDNS:

    socat -u UDP4-RECV:5353,ip-add-membership=224.0.0.251:eth0 /dev/null &
    tcpdump -i eth0 udp port 5353

DHCPv6:

    TODO

SSDP:

    socat -u UDP4-RECV:1900,ip-add-membership=239.255.255.250:eth0 /dev/null &
    tcpdump -i eth0 udp port 1900

## OPSEC considerations

## Counter-countermeasures
