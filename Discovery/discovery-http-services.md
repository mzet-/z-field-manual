
# Discovery: HTTP-based services

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

### Additional tools

 - Arch / Kali: `extra/xorg-server-xvfb / xvfb` package
 - [httprobe](https://github.com/tomnomnom/httprobe/releases/latest), [meg](https://github.com/tomnomnom/meg/releases/latest), [httpx](https://github.com/projectdiscovery/httpx/releases/latest)
 - [webintel.py](https://github.com/danamodio/webintel)
 - [Aquatone](https://github.com/michenriksen/aquatone/releases/latest) OR [webscreenshot.py](https://github.com/maaaaz/webscreenshot)
 - [Gobuster](https://github.com/OJ/gobuster/releases/latest)
 - [OPTIONALLY] [Eyeballer](https://github.com/bishopfox/eyeballer)
 - [OPTIONALLY] [ffuf](https://github.com/ffuf/ffuf/releases/latest)

### Discovery

Scanning for web-based services: on known hosts using `rawr-ports-long.txt` or `rawrPorts` collections

```
# fast:
cat hostsUp.txt | httpx -silent -ports $(rawrPorts) | tee -a urls-long.txt

# more ports, slower:
cat hostsUp.txt | httpx -silent -ports $(cat res/rawr-ports-long.txt | tr '\n' ',') | tee -a urls-long.txt
```

Scanning for web-based services: on whole IP range

```
# on most common ports: 8080 and 8000 and 8443:
cat IP-ranges.txt | httpx -silent -ports 8080,8000,8443 | tee urls-range-commonPorts.txt

# on additional common ports:
cat IP-ranges.txt | httpx -silent -ports 81,591,2082,2087,2095,2096,3000,8001,8008,8083,8834,8888 | tee -a urls-range-commonPorts.txt

# on rawr ports:
cat IP-ranges.txt | httpx -silent -ports $(rawrPorts) | tee urls-range-rawr.txt
```

Scanning for web-based services on known hosts (`hostsUp.txt`) on opened ports (`allPorts.txt`):

```
cat hostsUp.txt | httpx -silent -ports $(cat allPorts.txt | tr '\n' ',') | tee urls-hostsUp-allPorts.txt
```

Offline discovery of http(s) based services (from previous namp scans):

```
for i in $(python ~/bin/nparser.py -f vscan-1/base-vscan -s 'http' -l); do echo "http://$i" | grep -v -E '47001|5985|3389' | tee -a urls-nmap.txt; done
for i in $(python ~/bin/nparser.py -f vscan-1/base-vscan -s 'ssl\|http' -l); do echo "https://$i" | grep -v -E '47001|5985|5986|3389' | tee -a urls-nmap.txt; done
```

OR:

```
python3 ~/bin/nparser.py -f vscan-1/base-vscan -s ssl -l | grep -v -E '47001|5985|3389' | ./httpx -silent | tee urls.txt
python3 ~/bin/nparser.py -f vscan-1/base-vscan -s http -l | grep -v -E '47001|5985|3389' | ./httpx -silent | tee -a urls.txt
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
