
# Collection of useful payloads

## Asset discovery

```
## trusted DNS resolvers
wget https://raw.githubusercontent.com/mzet-/z-field-manual/master/res/trusted-dns-resolvers.txt -O ~/PAYLOADS/trusted-dns-resolvers.txt

## all wordlists from every dns enumeration tool... ever (as of 2019). Please excuse the lewd entries =/ ( over 1 Milion entries)
wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/f58e82c9abfa46a932eb92edbe6b18214141439b/all.txt -O ~/PAYLOADS/subdomains-jhaddix-compilation.txt
OR:
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O ~/PAYLOADS/subdomains-jhaddix-compilation.txt

## CommonSpeak2
wget https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt -O ~/PAYLOADS/commonspeak2.txt

## altdns words
wget https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -O ~/PAYLOADS/altdns-words.txt
```

## Content Discovery

```
wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O ~/PAYLOADS/dicc.txt

wget 'https://raw.githubusercontent.com/danielmiessler/RobotsDisallowed/master/curated.txt'; cat curated.txt | grep -v '*' | grep -v '?q=' | grep -v 'Wikipedia' | cut -d' ' -f1 | tr -d '#' > $HOME/PAYLOADS/robotsDissAllowed-curated.txt; rm curated.txt

wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -O ~/PAYLOADS/raft-large-directories.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-files.txt -O ~/PAYLOADS/raft-large-files.txt
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt

wget https://raw.githubusercontent.com/danielmiessler/RobotsDisallowed/master/top10000.txt -O ~/PAYLOADS/robotsDissallowed-top10000.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt -O ~/PAYLOADS/raft-medium-files.txt
wget https://raw.githubusercontent.com/danielmiessler/RobotsDisallowed/master/top1000.txt -O ~/PAYLOADS/robotsDissallowed-top1000.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt -O ~/PAYLOADS/raft-small-directories.txt
```

## Custom implemented tools

```
TODO
``

## Thirdparty tools

```
https://gchq.github.io/CyberChef/CyberChef_v9.55.0.zip
https://raw.githubusercontent.com/psypanda/hashID/master/hashid.py
https://github.com/reyammer/shellnoob

https://github.com/projectdiscovery/uncover/releases/latest
https://github.com/zmap/zmap/releases/latest
https://github.com/zmap/zgrab2/releases/latest

https://github.com/projectdiscovery/httpx/releases/latest
https://github.com/michenriksen/aquatone/releases/latest

https://github.com/ffuf/ffuf/releases/latest
https://github.com/OJ/gobuster/releases/latest

https://github.com/tomnomnom/meg/releases/latest
https://github.com/projectdiscovery/nuclei/releases/latest

https://github.com/zmap/zannotate
```

### snallygaster

About:

Looks for secret files on HTTP servers.

Get:

    wget https://raw.githubusercontent.com/hannob/snallygaster/main/snallygaster

### weak_passwords

About:

Generates set of typical passwords based on provided word (e.g. company name).

Get:

    wget https://raw.githubusercontent.com/averagesecurityguy/scripts/master/passwords/weak_passwords.py

### namemash

About:

Generates combinations of username based on privided name and surname tuples.

Get:

    wget https://gist.githubusercontent.com/superkojiman/11076951/raw/74f3de7740acb197ecfa8340d07d3926a95e5d46/namemash.py

