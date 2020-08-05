
# Flawed Remote Services

## Overview

MITRE ATT&CK mapping: T1021 / T1210

## Procedures

### SMB service

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

Additional enumeration: SMB protocol versions

```
nmap -n -sS -sV -T4 --open --script=smb-protocols -p445 -T4 -iL smbServices.txt -oA vscans/smbProtoVersions
nmap -n -sS -sV -T4 --open --script=smb-security-mode -p445 -T4 -iL smbServices.txt -oA vscans/smbProtoSigning
```

Additional enumeration: SMB general info

```
nmap -n -sU -sS -Pn -pT:139,445,U:137 -sV --script=smb-os-discovery,smb-security-mode,smb-system-info,smb2-capabilities,smb2-security-mode,smb2-time -T4 -iL smbServices.txt -oA vscans/smbServices-enumOverview.out

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
nmap -n --script=smb-enum-shares -T4 -p445 -iL smbServices.txt -oA vscans/smbEnumShares
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

Discovery (directly from the wire):

```
nmap -sS -Pn -n -T4 -p3389 -iL IP-ranges.txt -oG - --open | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee rdpServices.txt
```

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p3389 -l | tee rdpServices.txt
```

Enumeration (Nmap):

    # list Nmap's SNMP discovery scripts from https://github.com/leebaird/discover project:
    wget https://raw.githubusercontent.com/leebaird/discover/master/nse.sh
    grep 'nmap -iL $name/3389.txt' nse.sh | grep -o -P -e '--script=.*?[[:space:]]'
    
    # run scan:
    nmap -n -T4 -sS -p3389 --script <SCRIPTS> -iL rdpServices.txt

Enumeration (Metasploit):

```
wget https://raw.githubusercontent.com/leebaird/discover/master/resource/3389-rdp.rc
sed -i "s|setg RHOSTS.*|setg RHOSTS file:rdpServices.txt|g" 3389-rdp.rc
<modify '3389-rdp.rc' to disable not desired modules>
msfconsole -r 3389-rdp.rc
```

Vulnerability: ms12_020

```
use auxiliary/scanner/rdp/ms12_020_check
set RHOSTS file:rdpServices.txt
run
```

Vulnerability: CVE-2019-0708 aka 'Bluekeep'

```
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RDP_CLIENT_IP <my-IP>
set RHOSTS file:hostsUp.txt
set THREADS 7
run
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

Enumeration:

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

Discovery:

```
# from the wire:
wget https://raw.githubusercontent.com/portcullislabs/udp-proto-scanner/master/udp-proto-scanner.conf
wget https://raw.githubusercontent.com/portcullislabs/udp-proto-scanner/master/udp-proto-scanner.pl; chmod +x ./udp-proto-scanner.pl

ranges2IPs IP-ranges.txt > IP-list.txt
udp-proto-scanner.pl --probe_name SNMPv3GetRequest --file IP-list.txt | tee snmpServices.out
cat snmpServices.out | extractIPs > snmpServices.txt
```

Enumeration (Nmap):

    # list Nmap's SNMP discovery scripts from https://github.com/leebaird/discover project:
    wget https://raw.githubusercontent.com/leebaird/discover/master/nse.sh
    grep 'nmap -iL $name/161.txt' nse.sh | grep -o -P -e '--script=.*?[[:space:]]'
    
    # run scan:
    nmap -n -T4 -sU -p161 --script <SCRIPTS> -iL snmpServices.txt

Enumeration (Metasploit):

```
wget https://raw.githubusercontent.com/leebaird/discover/master/resource/161-udp-snmp.rc
sed -i "s|setg RHOSTS.*|setg RHOSTS file:snmpServices.txt|g" 161-udp-snmp.rc
msfconsole -r 161-udp-snmp.rc
```

Brute forcing for weak community strings:

```
# Spray with most common community strings:
onesixtyone -d -c <(echo -n -e "public\nprivate\nmanager") -i snmpServices.txt

# Check with Nmap's builtin community strings:
nmap -n -T4 -sU --script snmp-brute -iL snmpServices.txt

# Other lists:
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/common-snmp-community-strings.txt
# About ~3000 entries:
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/snmp.txt
onesixtyone -d -c common-snmp-community-strings.txt -i snmpServices.txt
```

Extract SNMP related information:

    snmpwalk -c <COMMUNITY_STRING> -v1 <IP>

Known vulnerabilities:

    https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp

### SMTP service

Ports:

    TCP: 25,587,465

Implementations:

    https://en.wikipedia.org/wiki/List_of_mail_server_software#SMTP

Discovery:

```
from the wire:
nmap -sS -Pn -n -p25,587,465 -iL IP-ranges.txt -oG - --open | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee smtpServices.txt
```

Enumeration:

```
wget https://raw.githubusercontent.com/leebaird/discover/master/nse.sh
grep 'nmap -iL $name/smtp.txt' nse.sh | grep -o -P -e '--script=.*?[[:space:]]'
nmap -n -T4 -sS -p25,587,465 --script <SCRIPTS> -iL smtpServices.txt -oA vscans/smtp-enum

wget https://raw.githubusercontent.com/leebaird/discover/master/resource/25-smtp.rc
sed -i "s|setg RHOSTS.*|setg RHOSTS file:smtpServices.txt|g" 25-smtp.rc
msfconsole -r 25-smtp.rc | tee vscans/smtp-enum.out
```

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

### POP3 / IMAP

### VoIP protocol suite

SIP Ports:

    TCP: 5060
    UDP: 5060

Skinny Client Control Protocol (SCCP) (Cisco proprietary protocol):

    TCP: 2000

Reference:

    https://en.wikipedia.org/wiki/Voice_over_IP
    https://en.wikipedia.org/wiki/Session_Initiation_Protocol

Implementations:

    https://en.wikipedia.org/wiki/List_of_SIP_software

Discovery (directly from the wire):

    nmap -sS -Pn -n -T4 -p5060 -iL IP-ranges.txt -oG - --open | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee sipServices.txt 

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p5060 -l | tee sipServices.txt
```

Enumeration (Nmap):

    # list Nmap's SNMP discovery scripts from https://github.com/leebaird/discover project:
    wget https://raw.githubusercontent.com/leebaird/discover/master/nse.sh
    grep 'nmap -iL $name/5060.txt' nse.sh | grep -o -P -e '--script=.*?[[:space:]]'
    
    # run scan:
    nmap -n -T4 -sU -p5060 --script <SCRIPTS> -iL sipServices.txt

Enumeration (Metasploit):

```
wget https://raw.githubusercontent.com/leebaird/discover/master/resource/5060-sip.rc
sed -i "s|setg RHOSTS.*|setg RHOSTS file:sipServices.txt|g" 5060-sip.rc
msfconsole -r 5060-sip.rc
```

Other tools / attacks:

```
https://hub.packtpub.com/how-to-attack-an-infrastructure-using-voip-exploitation-tutorial/
https://github.com/EnableSecurity/sipvicious
https://github.com/fozavci/viproy-voipkit
```

### Network storage/backup services

Ports:

    TCP: 21 (FTP)
    UDP: 69 (TFTP)
    TCP: 2049 (NFS)
    TCP: 3260 (iSCSI)
    TCP: 873 (rsync)
    TCP: 10000 (NDMP)
    TCP: 30000 (NDMPS)

    TCP: 9418 (Git)
    TCP: 3690 (SVN)

    TCP: 80,443 (HTTP/DAV aka WebDAV)

Discovery (directly from the wire):

    nmap -sS -Pn -n -T4 -p21,2049,3260,873,10000,30000,9418,3690 -iL IP-ranges.txt -oG - --open | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee netstorageServices.txt

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p21,2049,3260,873,10000,30000,9418,3690 -l | tee netstorageServices.txt
```

Enumeration (Nmap):

    # list Nmap's SNMP discovery scripts from https://github.com/leebaird/discover project:
    wget https://raw.githubusercontent.com/leebaird/discover/master/nse.sh
    grep -E 'nmap -iL \$name/(21|2049|3260|873|10000|30000|9418|3690).txt' nse.sh | grep -o -P -e '--script=.*?[[:space:]]'
    
    # run scan:
    nmap -n -PN -T4 --open -sS -sV -p21,2049,3260,873,10000,30000,9418,3690 --script <SCRIPTS> -iL netstorageServices.txt -oA vscans/netstorageServices-vscan

Enumeration (Metasploit):

```
TODO
```

### NTP service

Ports:

    UDP: 123

Discovery:

```
# from the wire:
udp-proto-scanner.pl --probe_name NTPRequest <IPs>
udp-proto-scanner.pl --probe_name ntp <IPs>
```

Enumeration:

```
nmap -n -T4 -sU -p123 --script=ntp-info,ntp-monlist -iL ntpServices.txt

wget https://raw.githubusercontent.com/leebaird/discover/master/resource/123-udp-ntp.rc
sed -i "s|setg RHOSTS.*|setg RHOSTS file:ntpServices.txt|g" 123-udp-ntp.rc
msfconsole -r 123-udp-ntp.rc
```

### NoSQL services

Ports:

    TCP: multiple ports

Currently looks for:

```
mongodb
cassandra
redis
splunk
elasticsearch
couchDB
```

Discovery (directly from the wire):

    nmap -sS -Pn -n -T4 -p27017,27018,27019,7199,7000,7001,9042,9160,61620,61621,6379,16379,26379,9997,8089,9200,9300,5984 -iL IP-ranges.txt -oG - --open | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee nosqlServices.txt 

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p27017,27018,27019,7199,7000,7001,9042,9160,61620,61621,6379,16379,26379,9997,8089,9200,9300,5984 -l | tee nosqlServices.txt
```

Enumeration (Nmap):

    # list Nmap's SNMP discovery scripts from https://github.com/leebaird/discover project:
    wget https://raw.githubusercontent.com/leebaird/discover/master/nse.sh
    grep -E 'nmap -iL \$name/(27017|27018|27019|7199|7000|7001|9042|9160|61620|61621|6379|16379|26379|9997|8089|9200|9300|5984).txt' nse.sh | grep -o -P -e '--script=.*?[[:space:]]'
    
    # run scan:
    nmap -n -PN -T4 -sS -sV --open -p27017,27018,27019,7199,7000,7001,9042,9160,61620,61621,6379,16379,26379,9997,8089,9200,9300,5984 --script <SCRIPTS> -iL nosqlServices.txt -oA vscans/nosqlServices-vscan

Enumeration (Metasploit):

```
TODO
```

Other tools / attacks:

```
TODO
```

## OPSEC considerations

## Counter-countermeasures
