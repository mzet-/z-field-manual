
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

Identifying web-based services (directly from the wire):

```
cat hostsUp.txt | ./httpx -silent -ports $(cat res/rawr-ports-long.txt | tr '\n' ',') | tee urls-long.txt
```

OR:

```
# rawr ports
cat IP-ranges.txt | ./httpx -silent -ports $(rawrPorts) | tee urls-rawr.txt

# ports 8080 and 8000 and 8443:
cat IP-ranges.txt | ./httpx -silent -ports 8080,8000,8443 | tee urls-8080-8000-8443.txt

# additional ports:
cat IP-ranges.txt | ./httpx -silent -ports 81,591,2082,2087,2095,2096,3000,8001,8008,8083,8834,8888 | tee urls-commonports.txt

# merge results:
cat urls-* > urls-all.txt
```

Identifying web-based services (from previous scans):

```
python ~/bin/nparser.py -p$(rawrPorts) -f pscans/all-rawrPN -l | ./httpx -silent | tee urls-rawr.txt
```

OR:

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
