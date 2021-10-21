
### package creation

```
https://wiki.archlinux.org/index.php/Creating_packages

# PKGBUILD template:
https://git.archlinux.org/pacman.git/plain/proto/PKGBUILD.proto
```

### basic pacman usage

```
# update whole system:
pacman -Syu
# show explicitly installed packages:
# pacman -Qe
# show deps packages:
# pacman -Qd
# Search for a package containing a file, e.g.: 
# pacman -Fy
# pacman -Fs ls
# clear pacman cache (saves lot of disk space):
# pacman -Sc
```

### Arch keyring ops

```
# refresching keyring:
pacman-key --init
pacman-key --populate
pacman-key --refresh-keys

# adding new key to the keyring:
# pacman-key -r keyid
$ pacman-key -f keyid
# pacman-key --lsign-key keyid
```

### deployment: AWS

Manually:

```
TODO
https://www.uplinklabs.net/projects/arch-linux-on-ec2/
```

Automation:

```
# creating new instance:
attack-fleet ec2new us-east-1
attack-fleet ec2show us-east-1
```

### deployment: Pi

```
TODO
```

### deployment: Qubes OS

```
TODO
```

### deployment: Docker

```
TODO
```

### deployment: VM (ova)

```
TODO
```

### Preparation: toolbox

```
# Run https://blackarch.org/strap.sh as root and follow the instructions.
$ curl -O https://blackarch.org/strap.sh

# The SHA1 sum should match:
$ curl -s https://blackarch.org/downloads.html | grep 'strap.sh | sha1sum -c'
$ sha1sum strap.sh

# Set execute bit
$ chmod +x strap.sh

# Run strap.sh
$ sudo ./strap.sh 

# directory structure:
mkdir {bin,res,LOGS,pscans,vscans}; mkdir -p PAYLOADS/{PASSWD,MISC}; mkdir -p IMPORTS/{TOOLS,MISC}

provisioning (from base machine):
scp ~/bin/hacking-helpers.inc arch@<ip>:bin

# tooling:
sudo pacman -Syu
sudo reboot
sudo -E bash
pacman -S gobuster dnsutils speedtest-cli wfuzz git screen p0f nmap certbot jq wget dnsrecon
pacman -S gau ffuf httpx hakrawler unfurl linkfinder secretfinder altdns massdns sublist3r amass
source ~/bin/hacking-helpers.inc
```

### Preparation: hardening

```
TODO
```
