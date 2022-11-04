
## Reference

3rd party collections:

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
https://github.com/mandiant/red_team_tool_countermeasures/blob/master/CVEs_red_team_tools.md
https://pwnies.com/previous/
https://github.com/mzet-/Nmap-for-Pen-Testers
```

```
https://github.com/detectify/ugly-duckling
https://github.com/projectdiscovery/nuclei
```

## Web applications

### CVE-2019-11510

**IDs**: CVE-2019-11510

    https://devco.re/blog/2019/09/02/attacking-ssl-vpn-part-3-the-golden-Pulse-Secure-ssl-vpn-rce-chain-with-Twitter-as-case-study/

Pre-auth Arbitrary File Reading from Pulse Secure SSL VPNs.

### CVE-2020-1938

Exploited in the wild: `curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | grep -B 1 -A 9 'CVE-2020-1938'`

## Native software (Windows)

### CVE-2017-0143

Notes:

```
Aka: ms17-01, EternalBlue (exploited by WannaCry)
Prereq:
  SMBv1 needs to be supported
  Needs connection to IPC$ share
  Tested on Windows XP, 2003, 7, 8, 8.1, 10, 2008, 2012 and 2016
Reference:
  https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html
  https://github.com/cldrn/nmap-nse-scripts/wiki/Notes-about-smb-vuln-ms17-010
```

Discovery:

```
nmap -sS --script smb-vuln-ms17-010 --max-hostgroup 3 -p445 -iL smbServices.txt --open -d -v | tee smb-vuln-ms17-010.out
nmap -sS -sU --script smb-vuln-ms17-010 --max-hostgroup 3 -pT:445,139,U:137 -iL smbServices.txt --open -d -v | tee smb-vuln-ms17-010.out

# if anonymous access to IPC$ is not allowed:
nmap -sS --script smb-vuln-ms17-010 --script-args='smbdomain="<domain>",smbusername="<user>",smbpassword=<passwd>' -pT:445 -iL smbServices.txt --open -v | tee smb-vuln-ms10-061.out
```

Exploitation:

    https://www.jamescarroll.me/blog/exploiting-ms17-010-with-metasploit-2020
    # for 32-bits machines:
    https://www.lmgsecurity.com/manually-exploiting-ms17-010/

### CVE-2019-0708

Notes:

```
Aka: Bluekeep
```

Discovery/Exploitation:

```
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RDP_CLIENT_IP <my-IP>
set RHOSTS file:hostsUp.txt
set THREADS 7
run
```

## Native software

## Client-side software
