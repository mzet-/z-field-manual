
<!-- MarkdownTOC depth=3 autolink=true -->

- [Intelligence Gathering](#intelligence-gathering)

<!-- /MarkdownTOC -->

# Intelligence Gathering

## Assets we are looking for

```
infrastructure
people
organization details
```

## Organization details

Manual review:

```
https://www.crunchbase.com/
https://opencorporates.com/
https://clutch.co/

Country specific:
https://pkt.pl (PL)
```

## Infrastructure recon

## People

```
https://linkedin.com
https://hunter.io/
```

Automated:

```
https://github.com/initstring/linkedin2username/releases/latest
linkedin2username.py -u <li-user> -c <company-name> -p <li-passwd>

https://github.com/m8sec/CrossLinked
```

### Transformation: domain to nameservers

    dnsrecon -d <domain>

### Transformation: domain to related domains
 
### Transformation: domain to subdomains

Manually:

    https://dnsdumpster.com
    https://crt.sh
    https://robtex.com

Automated: prereq

```
## amass config file
wget https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini -O amass-config.ini
<add your keys in [data_sources] section>

## trusted DNS resolvers
wget https://raw.githubusercontent.com/mzet-/z-field-manual/master/res/trusted-dns-resolvers.txt -O ~/PAYLOADS/trusted-dns-resolvers.txt

## all wordlists from every dns enumeration tool... ever (as of 2019). Please excuse the lewd entries =/ ( over 1 Milion entries)
wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/f58e82c9abfa46a932eb92edbe6b18214141439b/all.txt -O ~/PAYLOADS/subdomains-jhaddix-compilation.txt
OR ("only" 50 000 entries):
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O ~/PAYLOADS/subdomains-jhaddix-compilation.txt

## CommonSpeak2
wget https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt -O ~/PAYLOADS/commonspeak2.txt

## altdns words
wget https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -O ~/PAYLOADS/altdns-words.txt
```

Automated: all in one

    D=domain.com; subs-passive $D && subs-active $D; subs-merge $D; subs-mass-resolve $D && subs-altdns $D && subs-merge $D && subs-mass-resolve $D

Automated: step by step

### Attack opportunity: subdomain hijacking
