
# Discovery:

## Overview

MITRE ATT&CK mapping: N/A

## Procedures

Summary of alive hosts/devices per subnet:

```
In:
IP-ranges.txt - file with IP ranges in scope
pscans/*.xml - all hosts discovered so far

Out:
hostsUp-${i}.0.txt - file per each subnet with alive IPs

# version for /24 subnets
for i in $(cat IP-ranges.txt | cut -d'.' -f1,2,3); do echo "### Network $i.0 ###";  grep "$i" <(for f in $(ls pscans/*.xml); do ./gnxparse.py -ips $f 2>/dev/null; done) | sort -u -t '.' -k 4.1g | tee "hostsUp-${i}.0.txt"; done

# version for /16 subnets
for i in $(cat IP-ranges16.txt | cut -d'.' -f1,2); do echo "### Network $i.0.0 ###";  grep "$i" <(for f in $(ls pscans/*.xml); do ./gnxparse.py -ips $f 2>/dev/null; done) | sort -u -t '.' -k 4.1g | tee "hostsUp-${i}.0.0.txt"; done
```

Visualising network topology:

```
In:
IP-ranges.txt - file with IP ranges in scope
pscans/all-fast-onetime.nmap - result of full range fast (-F) scan

# pick at random 5 hosts per each subnet
for i in $(cat IP-ranges.txt | cut -d'.' -f1,2,3); do grep "$i" <(for f in $(ls pscans/*.xml); do ./gnxparse.py -ips $f 2>/dev/null; done) | sort -u -t '.' -k 4.1g | shuf -n 5 -; done | tee 5hosts-persubnet.txt
nmap -n -T4 -PN -sn --traceroute -iL 5hosts-persubnet.txt -oX netTopologyICMP.xml

# traceroute all hosts that repond to pings:
nmap -n -T4 -PN -sn --traceroute -iL hostsPings.txt -oX netTopologyICMP.xml --script targets-traceroute --script-args newtargets

zenmap netTopologyICMP.xml
OR:
wget https://gist.githubusercontent.com/B0073D/5079801/raw/bd5ccbd5f287813d71b4bc310f3f70dfaed106d0/nmap_trace_extract.py
python2 nmap_trace_extract.py
gephi -> layout:AtlasForce
```

Alternatives (TCP or UDP based) tracerouting:

```
# Comment:
# top 100 port scan is performed (-F)
# Nmap will initiate (TCP / UDP based) traceroute
# only if at least one of scanned ports are opened
# if not it will fallback to ICMP traceroute
nmap -PN -sS -n -F -T4 -iL 5hosts-persubnet.txt --traceroute --open -oX netTopologyTCP.xml
nmap -PN -sU -n -F -T4 -iL 5hosts-persubnet.txt --traceroute --open -oX netTopologyUDP.xml
# TCP and UDP combined. Scans top 16 TCP ports and 16 UDP ports, falls back to ICMP if scanned ports are closed:
nmap -PN -sUS -n --top-ports 16 -T4 -iL 5hosts-persubnet.txt --traceroute --open -oX netTopologyTCP-UDP.xml

zenmap netTopology{TCP,UDP,TCP-UDP}.xml
```

## OPSEC considerations

## Counter-countermeasures
