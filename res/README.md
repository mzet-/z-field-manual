
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
