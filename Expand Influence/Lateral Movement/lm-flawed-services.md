
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
nmap -sS -Pn -n -p445 -iL IP-ranges.txt -oG - --open -oA pscans/smb-discovery
cat pscans/smb-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee smbServices.txt
```

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p445 -l | tee smbServices.txt
```

Additional enumeration: SMB protocol versions

```
# for SMBv2+:
nmap -n -PN -sS -T4 --open --script=smb2-capabilities -p445 -T4 -iL smbServices.txt -oA vscans/smb2ProtoVersions --max-hostgroup 128

# for SMBv1:
nmap -n -PN -sS -T4 --open --script=smb-protocols -p445 -T4 -iL smbServices.txt -oA vscans/smbProtoVersions --max-hostgroup 128

# get IPs of machines supporting SMBv1:
grep -B10 SMBv1 vscans/smbProtoVersions.nmap | extractIPs
```

Additional enumeration: SMB signing

```

# for SMBv2+:
nmap -n -PN -sS -T4 --open --script=smb2-security-mode -p445 -T4 -iL smbServices.txt -oA vscans/smb2ProtoSigning --max-hostgroup 128

# for SMBv1:
nmap -n -PN -sS -T4 --open --script=smb-security-mode -p445 -T4 -iL smbServices.txt -oA vscans/smbProtoSigning --max-hostgroup 128

# extract hosts that do not require message signing (i.e., hosts that are vulnerable to MitM/SMB-relay attack:
# SMBv1:
grep -B 12 -E 'message_signing: disabled|message_signing: supported' pscans/smbProtoSigning.nmap | extractIPs
# SMBv2+:
grep -B10 -E 'Message signing enabled but not required|Message signing is disabled and not required!|Message signing is disabled!' vscans/smb2ProtoSigning.nmap |extractIPs
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
nmap -sS -sU --script smb-vuln-ms08-067.nse -pT:445,139,U:137 -iL smbServices.txt --open -d | tee smb-vuln-ms08-067.out

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
nmap -sS -sU --script smb-vuln-ms10-054.nse --script-args unsafe -pT:445,139,U:137 -iL smbServices.txt --open -d | tee smb-vuln-ms10-054.out
# grep for 'true' in smb-vuln-ms10-054.out
```

Vulnerability: ms10-06

```
Notes: 
Originally used by Stuxnet
In order for the check to work it needs access to at least one shared printer on the remote system
Reference: https://nmap.org/nsedoc/scripts/smb-vuln-ms10-061.html

Discovery:
nmap -sS -sU --script smb-vuln-ms10-061.nse -pT:445,139,U:137 -iL smbServices.txt --open -d | tee smb-vuln-ms10-061.out
```

Vulnerability: ms17-01

```
Notes:
EternalBlue (exploited by WannaCry)
Prereq:
  SMBv1 needs to be supported
  Needs connection to IPC$ share
Tested on Windows XP, 2003, 7, 8, 8.1, 10, 2008, 2012 and 2016
Reference:
  https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html
  https://github.com/cldrn/nmap-nse-scripts/wiki/Notes-about-smb-vuln-ms17-010

Discovery:
nmap -sS --script smb-vuln-ms17-010 --max-hostgroup 3 -p445 -iL smbServices.txt --open -d -v | tee smb-vuln-ms17-010.out
nmap -sS -sU --script smb-vuln-ms17-010 --max-hostgroup 3 -pT:445,139,U:137 -iL smbServices.txt --open -d -v | tee smb-vuln-ms17-010.out

# if anonymous access to IPC$ is not allowed:
nmap -sS --script smb-vuln-ms17-010 --script-args='smbdomain="<domain>",smbusername="<user>",smbpassword=<passwd>' -pT:445 -iL smbServices.txt --open -v | tee smb-vuln-ms10-061.out
```

### RDP service

Discovery (directly from the wire):

```
nmap -sS -Pn -n -T4 -p3389 -iL IP-ranges.txt --open -oA pscans/rdp-discovery
cat pscans/rdp-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee rdpServices.txt
```

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p3389 -l | tee rdpServices.txt
```

Enumeration (Nmap):

    # list Nmap's RDP discovery scripts from https://github.com/leebaird/discover project:
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
https://research.nccgroup.com/2021/01/21/mssql-lateral-movement/
```

Discovery:

```
# from the wire:
nmap -sS -Pn -n -T4 -p1433 -iL IP-ranges.txt --open -oA pscans/mssql-discovery
cat pscans/mssql-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee mssqlServices.txt

udp-proto-scanner.pl --probe_name ms-sql <IPs> | tee udpprobe-mssql.out | extractIPs >> mssqlServices.txt
sort -u mssqlServices.txt -o mssqlServices.txt

nmap --script broadcast-ms-sql-discover

# from previous scans:
python nparser.py -f vscans/vscanlatest -sms-sql -l | cut -d: -f1 |tee mssqlServices.txt
# ports:
python nparser.py -f vscans/vscanlatest -sms-sql -l | cut -d: -f2 | tr '\n' ','
```

Enumeration:

    nmap -n -sS -sV -p<ports> --script=ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password,ms-sql-dump-hashes --script-args mssql.instance-port=<ports> -iL mssqlServices.txt -d -oA vscans/mssql-enum

Brute force attack (default creds):

    wget https://raw.githubusercontent.com/wintrmvte/medusa_combo_files/master/mssql_default_66.txt
    medusa -M mssql -C mssql_default_66.txt -H mssqlServices.txt -T 4 -t 1 -F

Brute force attack (weak passwords):

    wget https://raw.githubusercontent.com/x90skysn3k/brutespray/master/wordlist/mssql/user -O mssql-users.txt
    wget https://raw.githubusercontent.com/x90skysn3k/brutespray/master/wordlist/mssql/password -O mssql-passwds.txt
    hydra -s 1433 -t 1 -T 6 -L mssql-users.txt -P mssql-passwds.txt -M mssqlServices.txt mssql

### WinRM service

Ports:

```
TCP: 5985, 5986, 47001
```

**Testing**

Discovery (directly from the wire):

```
nmap -sS -Pn -n -p5985,5986,47001 -iL IP-ranges.txt -oG - --open -oA pscans/winrmMachines
cat pscans/winrmMachines.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee winrmServices.txt
```

Discovery (from previous scans):

```
python3 $HOME/bin/nparser.py -f vscanlatest -p88 -l | cut -d':' -f1 | tee winrmServices.txt
```



### Windows Kerberos

Ports:

```
TCP: 88
```

**Testing**

Discovery (directly from the wire):

```
nmap -sS -Pn -n -p88 -iL IP-ranges.txt -oG - --open -oA pscans/kerberos88
cat pscans/kerberos88.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee kerberos88Services.txt
```

Discovery (from previous scans):

```
python3 $HOME/bin/nparser.py -f vscanlatest -p88 -l | cut -d':' -f1 | tee kerberos88Services.txt
```

**Notable vulnerabilities**

Zerologon (CVE-2020-1472)

```
Reference: https://www.secura.com/blog/zero-logon

git clone https://github.com/SecuraBV/CVE-2020-1472
cd CVE-2020-1472
python3 zerologon_tester.py -h
```

### MSRPC

Background:

    TODO

Discovery:

```
nmap -n -sU -sS -Pn -pT:135 -T4 --open
```

### MSMQ

Background:

    TODO

Discovery:

```
nmap -n -sU -sS -Pn -pT:1801 -T4 --open
```

Ports:

    https://docs.microsoft.com/en-US/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements#message-queuing

### Remote Administration for IIS

Background:

    https://docs.microsoft.com/en-us/iis/manage/remote-administration/remote-administration-for-iis-manager

Discovery:

```
nmap -sS -Pn -n -p8172 -iL IP-ranges.txt -oG - --open -oA pscans/iis-manager8172
cat pscans/iis-manager8172.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee iisManagerServices.txt
```


### Other Windows services

Background:

    https://support.microsoft.com/en-us/help/832017/service-overview-and-network-port-requirements-for-windows


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
    nmap -n -T4 -sU -p161 --script <SCRIPTS> -iL snmpServices.txt -oA vscans/snmp-enum

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
nmap -sS -Pn -n -p25,587,465 -iL IP-ranges.txt --open -oA pscans/smtp-discovery
cat pscans/smtp-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee smtpServices.txt
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

Useful links:

```
https://www.blackhillsinfosec.com/how-to-test-for-open-mail-relays/
https://luemmelsec.github.io/Pentest-Everything-SMTP/
https://cert.pl/posts/2021/10/mechanizmy-weryfikacji-nadawcy-wiadomosci/
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
    TCP: 548 (AFP aka AppleTalk aka Netatalk)

    TCP: 9418 (Git)
    TCP: 3690 (SVN)

    TCP: 80,443 (HTTP/DAV aka WebDAV)

Discovery (directly from the wire):

    nmap -sS -Pn -n -T4 --open -p21,2049,3260,873,10000,30000,9418,3690,548 -iL IP-ranges.txt -oA pscans/net-storage-discovery
    cat pscans/net-storage-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee netstorageServices.txt

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p21,2049,3260,873,10000,30000,9418,3690,548 -l | tee netstorageServices.txt
```

Enumeration (Nmap):

    # list Nmap's SNMP discovery scripts from https://github.com/leebaird/discover project:
    wget https://raw.githubusercontent.com/leebaird/discover/master/nse.sh
    grep -E 'nmap -iL \$name/(21|2049|3260|873|10000|30000|9418|3690|548).txt' nse.sh | grep -o -P -e '--script=.*?[[:space:]]'
    
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
neo4j (https://neo4j.com/docs/operations-manual/current/configuration/ports/)
```

Discovery (directly from the wire):

    nmap -sS -Pn -n -T4 -p27017,27018,27019,7199,7000,7001,9042,9160,61620,61621,6379,16379,26379,9997,8089,9200,9300,5984,6362-6372,7474,7473,7687,5000,6000,2003,2004,3637 -iL IP-ranges.txt --open -oA pscans/nosql-discovery 
    cat pscans/nosql-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee nosqlServices.txt 

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

### SSH

Ports:

    TCP: 22


Overview:

    -

Discovery (directly from the wire):

    nmap -sS -Pn -n -T4 -p22 -iL IP-ranges.txt --open -oA pscans/ssh-discovery
    cat pscans/ssh-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee sshServices.txt

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p22 -l | tee sshServices.txt
```

Enumeration (Nmap):

```
TODO
```

Enumeration (custom):

```
TODO
```

Brute forcing:

```
wget https://raw.githubusercontent.com/redcode-labs/meducat/master/medusa-combo-files/ssh_default_131.txt
medusa -C ssh_default_131.txt -M ssh -H sshServices.txt -F -t 1 -T 8 -O medusa-ssh.out
```

Reference:

```
SSH Lateral Movement Cheat Sheet:
https://highon.coffee/blog/ssh-lateral-movement-cheat-sheet/
```


### Legacy remote shells

Ports:

    TCP: 23 (telnet),177 (XDMCP),512 (rexec),513 (rlogin),514 (RSH)
    UDP: 177 (XDMCP)


Overview:

    -

Discovery (directly from the wire):

    nmap -sS -Pn -n -T4 -p23,177,512,513,514 -iL IP-ranges.txt --open -oA pscans/legacy-shells-discovery
    cat pscans/legacy-shells-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee legacyshellsServices.txt

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p23,177,512,513,514 -l | tee legacyshellsServices.txt
```

Enumeration (Nmap):

```
nmap -sU -p 177 --script xdmcp-discover <ip>
```

Enumeration (custom):

```
telnet <ip>
rexec <ip>
rlogin <ip>
rsh <ip>
```

Brute forcing (telnet):

```
wget https://raw.githubusercontent.com/redcode-labs/medusa_combo_files/master/telnet_default_706.txt
medusa -C telnet_default_706.txt -M telnet -H legacyshellsServices.txt -t 2 -T 12 -O medusa-telnet.out
```

Brute forcing:

```
nmap -p 512 --script rexec-brute <ip>

nmap -p 513 --script rlogin-brute <ip>
```

### BMC/IPMI

Ports:

    UDP: 623
    TCP: 623


**Overview**

Characteristics:

 - BMCs are often implemented as embedded ARM systems, running Linux and connected directly to the southbridge of the host system's motherboard. 
 - Network access is obtained either via 'sideband' access to an existing network card or through a dedicated interface.
 - Ports are directly exposed by this embedded system (so there are not visible via netstat on the host OS) (?)

Used for:

Out-of band host management / emulation of physical access to the machine (i.e. access to grub)

BMC/IPMI solutions by various vendors:

HP iLO, Dell DRAC, Sun ILOM, Fujitsu iRMC, IBM IMM, and Supermicro IPMI.

Typical exposure:

```
Web panel
IPMI protocol implementation (ports: 623 UDP; sometimes 623 TCP)
Telnet/SSH access
```

**Testing**

Discovery (directly from the wire):

    # UDP:
    nmap -n -sU -T4 -iL IP-ranges.txt -p623 --open -oA vscans/udp623
    cat vscans/udp623.gnmap | grep 'Ports: 623/open/udp/' | cut -d' ' -f2 | tee ipmiServices.txt

    # TCP:
    nmap -sS -Pn -n -T4 -p623 -iL IP-ranges.txt --open -oA pscans/ipmi-tcp-discovery
    cat pscans/ipmi-tcp-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee ipmi-tcpServices.txt

Discovery (from previous scans):

```
# UDP-based:
TODO

# TCP-based:
python scripts/nparser.py -f vscanlatest -p623 -l | tee ipmi-tcpServices.txt
```

Enumeration (Nmap):

```
nmap -sU -p 623 --script ipmi-version <ip>
```

Grabbing hashes (possible due to design flaw in IPMI 2.0 protocol specification):

```
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS file:ipmiServices.txt
run
```

**References**

A Penetration Tester's Guide to IPMI and BMCs:

    https://blog.rapid7.com/2013/07/02/a-penetration-testers-guide-to-ipmi/

BMC practical exploitation (rebooting -> changing kernel boot params via grub: init=/bin/bash -> booting to root):

```
https://medium.com/bugbountywriteup/how-a-badly-configured-db-allowed-us-to-own-an-entire-cloud-of-over-25k-hosts-part-1-2-8846beab691e
https://medium.com/bugbountywriteup/how-a-badly-configured-db-allowed-us-to-own-an-entire-cloud-of-over-25k-hosts-part-2-2-5a63da194bc1
```

SuperMicro IPMI (additional) default password:

    https://packetstormsecurity.com/files/105730/Supermicro-IPMI-Default-Accounts.html

Exploit: Dell iDRAC7 and iDRAC8 Devices Code Injection Vulnerability (RCE) (firmware: <  2.52.52.52):

    https://github.com/KraudSecurity/Exploits/blob/master/CVE-2018-1207/CVE-2018-1207.py

### Printers

Ports:

    TCP: 515,631,9100


Overview:

    -

Discovery (directly from the wire):

    nmap -sS -Pn -n -T4 -p515,631,9100 -iL IP-ranges.txt --open -oA pscans/printer-discovery
    cat pscans/printer-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee printersServices.txt

Discovery (from previous scans):

```
python scripts/nparser.py -f vscanlatest -p515,631,9100 -l | tee printersServices.txt
```

### Java-based services

Ports:

    TCP (Java Debug Wire Protocol): 3999,5000,5005,8000,8453,8787-8788,9001,18000
    Java RMI registry: 1098,1099,8901,8902,8903
    Java JMX default ports used by various or commonly seen in the wild: 1090,1050,1100,9999...
    See (TODO):
    https://github.com/qtc-de/remote-method-guesser/blob/eb265338f6012b64c7590ec0eb66712e3b035994/src/config.properties
    https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/lib/msf/core/exploit/remote/java/rmi/util.rb
    https://github.com/eclipse/jetty.project/blob/cb127793e5d8b5c5730b964392a9a905ba49191d/jetty-jmx/src/test/java/org/eclipse/jetty/jmx/ConnectorServerTest.java
    https://www.redtimmy.com/jmx-rmi-multiple-applications-rce/
    https://tomcat.apache.org/tomcat-7.0-doc/monitoring.html
    https://docs.vmware.com/en/VMware-vRealize-Operations-for-Horizon/6.7/com.vmware.vrealize.horizon.admin.doc/GUID-1467821F-F3F9-458C-A9DE-3EFA517C44DF.html
    https://www.ibm.com/docs/en/mpf/8.0.0?topic=prerequisites-configuring-jmx-connection-apache-tomcat
    https://svn.nmap.org/nmap/scripts/rmi-dumpregistry.nse

Overview: RMI

    # very consie but good overview of the technology and available attack vectors:
    https://book.hacktricks.xyz/network-services-pentesting/1099-pentesting-java-rmi

Overview: JMX

    https://mogwailabs.de/en/blog/2019/04/attacking-rmi-based-jmx-services/

Overview: Java Debug Wire Protocol

Discovery (directly from the wire):

    # Java Debug Wire Protocol:
    nmap -sS -Pn -n -T4 -p3999,5000,5005,8000,8453,8787-8788,9001,18000 -iL IP-ranges.txt --open -oA pscans/java-wire-debugger-discovery
    cat pscans/java-wire-debugger-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee java-wire-debugger-discoveryServices.txt

    # Java RMI registry:
    nmap -sS -Pn -n -T4 -p1098,1099 -iL IP-ranges.txt --open -oA pscans/java-rmi
    cat pscans/java-rmi.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee java-rmiServices.txt
 

Discovery (from previous scans):

```
# Java Debug Wire Protocol:
python scripts/nparser.py -f vscanlatest -p3999,5000,5005,8000,8453,8787-8788,9001,18000 -l | tee printersServices.txt

# Java RMI:
python scripts/nparser.py -f vscanlatest -p1098,1099 -l | tee java-rmiServices.txt
```

```
nmap --script=rmi-dumpregistry 192.168.10.97 -p1099

https://github.com/qtc-de/remote-method-guesser/releases/latest
java -jar rmg-4.3.1-jar-with-dependencies.jar -h
```

### VNC

Ports:

    TCP (Java Debug Wire Protocol): 3999,5000,5005,8000,8453,8787-8788,9001,18000

Overview:

    -

Discovery (directly from the wire):

    # Java Debug Wire Protocol:
    nmap -sS -Pn -n -T4 -p3999,5000,5005,8000,8453,8787-8788,9001,18000 -iL IP-ranges.txt --open -oA pscans/java-wire-debugger-discovery
    cat pscans/java-wire-debugger-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee java-wire-debugger-discoveryServices.txt

Discovery (from previous scans):

```
# Java Debug Wire Protocol:
python scripts/nparser.py -f vscanlatest -p3999,5000,5005,8000,8453,8787-8788,9001,18000 -l | tee java-wire-debugger-discoveryServices.txt
```

### Oracle

Ports:

    TCP (Java Debug Wire Protocol): 3999,5000,5005,8000,8453,8787-8788,9001,18000

Overview:

    -

Discovery (directly from the wire):

    # Java Debug Wire Protocol:
    nmap -sS -Pn -n -T4 -p3999,5000,5005,8000,8453,8787-8788,9001,18000 -iL IP-ranges.txt --open -oA pscans/java-wire-debugger-discovery
    cat pscans/java-wire-debugger-discovery.gnmap | grep -E -v 'Nmap|Status' | cut -d' ' -f2 | tee java-wire-debugger-discoveryServices.txt

Discovery (from previous scans):

```
# Java Debug Wire Protocol:
python scripts/nparser.py -f vscanlatest -p3999,5000,5005,8000,8453,8787-8788,9001,18000 -l | tee printersServices.txt
```

### VMware

Overview

```
https://esxi-patches.v-front.de/
```

Discovery (directly from the wire): via SLP (service location protocol) endpoints

    # use Nmap 7.80 as 7.90 and 7.91 have broken UDP scanning):
    wget https://nmap.org/dist/nmap-7.92.tar.bz2

    # looking for SLP (service location protocol):
    nmap -n -sU -T4 -iL IP-ranges.txt -p427 --open -oA vscans/srvloc427
    cat vscans/srvloc427.gnmap | grep 'Ports: 427/open/udp/' | cut -d' ' -f2 | tee srvlocServices.txt

Vulnerability: in OpenSLP as used by ESXi (CVE-2020-3992 / CVE-2021-21974)

```
wget https://raw.githubusercontent.com/mzet-/Nmap-for-Pen-Testers/master/scripts/vmware-svrloc-vulns.nse -O scripts/vmware-svrloc-vulns.nse
wget https://raw.githubusercontent.com/mzet-/Nmap-for-Pen-Testers/master/nselib/srvloc.lua -O nselib/srvloc.lua

# display versions:
./nmap-7.92/nmap -n -sU -p427 -script=./vmware-svrloc-vulns.nse -iL srvlocServices.txt -sV -oG - | grep -v 'Status: Up'

# check:
./nmap-7.92/nmap -sU -p427 --script=./vmware-svrloc-vulns.nse -iL srvlocServices.txt
```

## OPSEC considerations

## Counter-countermeasures
