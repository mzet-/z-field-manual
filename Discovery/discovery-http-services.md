
# Discovery: HTTP-based services

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

Prereq:

 - [gnmap2urls.sh](scripts/gnmap2urls.sh)
 - Arch / Kali: `extra/xorg-server-xvfb / xvfb` package
 - [httprobe](https://github.com/tomnomnom/httprobe/releases/latest)
 - [Aquatone](https://github.com/michenriksen/aquatone/releases/latest) OR [webscreenshot.py](https://github.com/maaaaz/webscreenshot)
 - [OPTIONALLY] [Eyeballer](https://github.com/bishopfox/eyeballer)

Identifying web-based services:

```
TODO: httprobe
```

Visual discovery of interesting web-based applications:

```
gnmap2urls.sh all-vulnScan.out.gnmap | tee urls0.txt

python webscreenshot.py -v -r chromium --no-xserver -i ../urls0.txt
OR
cat urls0.txt | ./aquatone -threads 5 -out aquatone-IPs.out/
```

## OPSEC considerations

## Counter-countermeasures
