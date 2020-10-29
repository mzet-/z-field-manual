
# Discovery: HTTP-based services

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

### Additional tools

 - Arch / Kali: `extra/xorg-server-xvfb / xvfb` package
 - [httprobe](https://github.com/tomnomnom/httprobe/releases/latest), [meg](https://github.com/tomnomnom/meg)
 - [webintel.py](https://github.com/danamodio/webintel)
 - [Aquatone](https://github.com/michenriksen/aquatone/releases/latest) OR [webscreenshot.py](https://github.com/maaaaz/webscreenshot)
 - [OPTIONALLY] [Eyeballer](https://github.com/bishopfox/eyeballer)
 - [OPTIONALLY] [ffuf](https://github.com/ffuf/ffuf)

### Discovery

Identifying web-based services (directly from the wire):

```
# ports 80 and 443 only:
cat hostsUp.txt | ./httprobe -c 17 | tee httprobe-hostsUp-80-443.out

# ports 8080 and 8000 and 8443:
cat hostsUp.txt | ./httprobe -s -c 17 -p http:8080 -p http:8000 -p https:8443 | tee httprobe-hostsUp-8080-8000-8443.out

# additional ports:
cat hostsUp.txt | ./httprobe -s -c 17 -p http:81 -p http:591 -p http:2082 -p http:2087 -p http:2095 -p http:2096 -p http:3000 -p http:8001 -p http:8008 -p http:8083 -p http:8834 -p http:8888 | tee httprobe-hostsUp-large.out

# merge results:
cat httprobe-* > urls-all.txt
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

"One request" web app fingerprinting:

    python webintel.py -t 7 -iL urls-all.txt | tee webintel-all.out
    OR (from previous scans):
    python webintel.py -t 7 -iL urls-all.txt | tee webintel-all.out


## OPSEC considerations

## Counter-countermeasures
