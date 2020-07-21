
# Discovery: HTTP-based services

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

### Additional tools

 - [gnmap2urls.sh](scripts/gnmap2urls.sh)
 - Arch / Kali: `extra/xorg-server-xvfb / xvfb` package
 - [httprobe](https://github.com/tomnomnom/httprobe/releases/latest), [meg](https://github.com/tomnomnom/meg)
 - [webintel.py](https://github.com/danamodio/webintel)
 - [Aquatone](https://github.com/michenriksen/aquatone/releases/latest) OR [webscreenshot.py](https://github.com/maaaaz/webscreenshot)
 - [nikto vuln db file](https://raw.githubusercontent.com/sullo/nikto/master/program/databases/db_tests)
 - [OPTIONALLY] [Eyeballer](https://github.com/bishopfox/eyeballer)

### Discovery

Identifying web-based services (directly from the wire):

```
TODO: httprobe
```

Identifying web-based services (from previous scans):

```
TODO: nparser.py
```

### Fingerprinting

Visual discovery of interesting web-based applications:

```
python webscreenshot.py -v -r chromium --no-xserver -i ../urls0.txt
OR
cat urls0.txt | ./aquatone -threads 5 -out aquatone-IPs.out/
```

Scraping certificate 'Common Name' string from TLS enabled services:

```
scripts/
```

### Vulnerability discovery

    nmap -n -PN -sS -sV --version-intensity 2 --script=http-enum --script-args=http-enum.fingerprintfile=./http-fingerprints.lua,http-fingerprints.nikto-db-path=./db_nikto_tests100 -T4 -iL http-ips.txt -p80,443,$(cat http-ports.txt | tr '\n' ',') -oA vscans/http-nikto-vuln-scan

### Web-based authentication panels

Default credentials:

Weak/simple credentials:

```
TODO
```

## OPSEC considerations

## Counter-countermeasures
