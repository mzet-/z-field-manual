
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

## Techniques

### Transformation: domain to nameservers

    dnsrecon -d <domain>
 
### Transformation: domain to subdomains

Manually:

    https://dnsdumpster.com/
    https://crt.sh

Automated: prereq

Automated: all in one

    D=domain.com; subs-passive $D && subs-active $D; subs-merge $D; subs-mass-resolve $D && subs-altdns $D && subs-merge $D && subs-mass-resolve $D

Automated: step by step

### Attack opportunity: subdomain hijacking
