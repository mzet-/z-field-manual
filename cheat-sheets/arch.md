
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
# refreshing keyring:
pacman-key --init
pacman-key --populate
pacman-key --refresh-keys
# OR (faster):
pacman -S archlinux-keyring

# adding new key to the keyring:
# pacman-key -r keyid
$ pacman-key -f keyid
# pacman-key --lsign-key keyid

# wiping out whole trustdb and recreating it:
https://bbs.archlinux.org/viewtopic.php?pid=1837082#p1837082
```

### deployment: AWS

Manually:

```
Since late 2021 Uplink Labs does not prepare new Arch AMIs:
https://www.uplinklabs.net/projects/arch-linux-on-ec2/

Links for current AWS AMIs can be found here:
https://wiki.archlinux.org/title/Arch_Linux_AMIs_for_Amazon_Web_Services

Instruction on how to prepare your own Arch AMI:
http://mathcom.com/arch.aws.ami.html#_final_set_up
```

Automation:

```
# creating new instance:
attack-fleet ec2new us-east-1
attack-fleet ec2show us-east-1

# stopping the instance:
attack-fleet ec2ops stop us-east-1 <instance-id> 
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
## Directory structure prep and provisioning:
attack-fleet ec2show us-east-1
export IP=<ip>; export user=arch
ssh -i $HOME/.ssh/key.pem "$user"@"$ip" 'mkdir {bin,res,LOGS,pscans,vscans}; mkdir -p PAYLOADS/{PASSWD,MISC}; mkdir -p IMPORTS/{TOOLS,MISC}'
scp -i $HOME/.ssh/key.pem $HOME/bin/hacking-helpers.inc "$user"@"$ip":bin

## jump to the machine
ssh -i $HOME/.ssh/key.pem "$user"@"$ip"

## Refresh keys and update
# pacman -S archlinux-keyring
# OR:
# pacman-key --init
# pacman-key --populate
# select fastest mirror:
# reflector [--country <country>] --protocol https --score 20 --sort rate --save /etc/pacman.d/mirrorlist
# pacman -Syu
# reboot

## Deploy BlackArch
# Run https://blackarch.org/strap.sh as root and follow the instructions.
$ curl -O https://blackarch.org/strap.sh
# The SHA1 sum should match:
$ curl -s https://blackarch.org/downloads.html | grep 'strap.sh | sha1sum -c'
$ sha1sum strap.sh
# Set execute bit
$ chmod +x strap.sh
# Run strap.sh
$ sudo ./strap.sh 

## Deploy baseline toolbox
sudo pacman -Syu
sudo -E bash
# from Arch:
pacman -S net-tools gobuster dnsutils speedtest-cli wfuzz git screen p0f nmap certbot jq wget dnsrecon
# hacking helpers include:
source ~/bin/hacking-helpers.inc
# from Blackarch:
pacman -S gau ffuf httpx hakrawler unfurl linkfinder secretfinder altdns massdns sublist3r amass gobuster dnsrecon
```

### Preparation: hardening

```
TODO
```
