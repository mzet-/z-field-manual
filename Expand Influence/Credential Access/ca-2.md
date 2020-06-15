
# DNS Poisoning via DHCPv6 and SMB Relay

## Overview

MITRE ATT&CK mapping: N/A

Reference:

```
https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/
https://github.com/fox-it/mitm6
```

## Procedures

### Attack execution

```
git clone https://github.com/fox-it/mitm6.git
cd mitm6; pip install .; cd ..
python3 mitm6/mitm6/mitm6.py -h
python3 mitm6/mitm6/mitm6.py -d <domain>
```

### Additional notes

    https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/

## OPSEC considerations

## Counter-countermeasures
