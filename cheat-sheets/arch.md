
## Arch usage

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

### VPN

```
screen
route -n
route add -host <LOCAL_IP> gw <GW_IP> 
openvpn config.ovpn
```

## Deployments

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

# terminating (wiping out disk content) the instance:
attack-fleet ec2ops kill us-east-1 <instance-id> 
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
Official Arch docker image:
https://hub.docker.com/_/archlinux?tab=description
```

### deployment: VM (ova)

```
TODO
```

### deployment: VM (KVM+Qemu)

```
creating bridge fo QEMU:
https://wiki.archlinux.org/index.php/Network_bridge#With_iproute2
https://wiki.archlinux.org/index.php/QEMU#Bridged_networking_using_qemu-bridge-helper
https://serverfault.com/questions/879926/how-do-i-use-qemu-bridge-helper-to-get-a-virtual-server-running-on-my-local-netw
https://serverfault.com/questions/130134/kvm-network-bridge-with-two-nics


dd if=/dev/zero of=arch-1.img bs=1M count=4095
sudo mkfs.ext4 -F arch-1.img
sudo mount -o loop arch-1.img mnt
sudo pacstrap mnt base dhcpcd net-tools openvpn vim openssh sudo xorg-xauth xorg-xclock xorg-fonts-type1

Encrypted:
dd if=/dev/zero of=arch-luks.img bs=1M count=1024
cryptsetup --verify-passphrase luksFormat arch-luks.img -c aes -s 256 -h sha256
sudo cryptsetup luksOpen arch-luks.img arch-luks
sudo mkfs -t ext4 -m 1 -O dir_index,filetype,sparse_super /dev/mapper/arch-luks
sudo cryptsetup luksClose arch-luks

https://www.collabora.com/news-and-blog/blog/2019/03/20/bootstraping-a-minimal-arch-linux-image/

Configuration and additional packages (on guest):
sudo mount -o loop arch-1.img mnt
echo -e "PermitRootLogin yes\nX11Forwarding yes" >> mnt/etc/ssh/sshd_config

systemctl enable dhcpcd
systemctl start dhcpcd
systemctl enable sshd
systemctl start sshd

New /home perparation:

creating encrypted partition:
export CODENAME=<codename>
dd if=/dev/zero of=$CODENAME.img bs=1M count=1024
cryptsetup --verify-passphrase luksFormat $CODENAME.img -c aes -s 256 -h sha256
sudo cryptsetup luksOpen $CODENAME.img $CODENAME
sudo mkfs -t ext4 -m 1 -O dir_index,filetype,sparse_super /dev/mapper/$CODENAME
sudo cryptsetup luksClose $CODENAME

get UUID:
file $CODENAME.img

sudo mount -o loop arch-1.img mnt

sudo sh -c "echo \"/dev/mapper/$CODENAME /home ext4 defaults 0 2\" > mnt/etc/fstab"
sudo sh -c "echo \"$CODENAME UUID=<uuid> none\" > mnt/etc/crypttab"

sudo arch-chroot mnt
passwd
useradd -m <CODENAME>
passwd <CODENAME>
TODO: add <CODENAME> to sudoers

sudo umount mnt/

starting and provisioning:
qemu-system-x86_64 -hda arch-1.img -hdb $CODENAME.img -kernel ./linux-5.7.19/arch/x86/boot/bzImage -append "root=/dev/sda rw console=ttyS0" --enable-kvm -nographic -m 2G -pidfile vm.pid -net nic -net user,hostfwd=tcp::2022-:22

scp -P2022 ca.crt openvpn.conf root@127.0.0.1:

ssh -D1234 root@127.0.0.1 -p 2022

Preparing kernel:
https://vez.mrsk.me/linux-hardening.html#kern

Hardening:
get hardening patch: https://github.com/anthraxx/linux-hardened/releases
wget https://github.com/anthraxx/linux-hardened/releases/download/5.7.19.a/linux-hardened-5.7.19.a.patch
get kernel:
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.7.19.tar.xz

patch kernel:
cd linux-5.7.19
patch -p1 < ../linux-hardened-5.7.19.a.patch

configure kernel:
make menuconfig
make kvmconfig
cat <<EOF >.config-fragment
CONFIG_TUN=y
CONFIG_DM_CRYPT=y
EOF
./scripts/kconfig/merge_config.sh .config .config-fragment

compile:
make -j5

sudo make INSTALL_MOD_PATH=../mnt/ modules_install
cd ..
sudo umount mnt



Starting/Stopping:
qemu-system-x86_64 -hda arch-1.img -hdb $CODENAME.img -kernel ./linux/arch/x86/boot/bzImage -append "root=/dev/sda rw console=ttyS0" --enable-kvm -nographic -m 2G -pidfile vm.pid -net nic -net user,hostfwd=tcp::2022-:22
sudo sh -c 'kill $(cat vm.pid)'

run with hardened kernel:
qemu-system-x86_64 -hda arch-1.img -hdb $CODENAME.img -kernel ./linux-5.7.19/arch/x86/boot/bzImage -append "root=/dev/sda rw console=ttyS0" --enable-kvm -nographic -m 2G -pidfile vm.pid -net nic -net user,hostfwd=tcp::2022-:22

ssh root@127.0.0.1 -p 2022

Misc:
Resizing image (not verified):
https://superuser.com/questions/24838/is-it-possible-to-resize-a-qemu-disk-image
```

## Provisioning

### preparation: toolbox

```
## Directory structure prep and provisioning:
attack-fleet ec2show us-east-1
export ip=<ip>; export user=arch
ssh -i $HOME/.ssh/key.pem "$user"@"$ip" 'mkdir {bin,res,LOGS,pscans,vscans}; mkdir -p PAYLOADS/{PASSWD,MISC}; mkdir -p IMPORTS/{TOOLS,MISC}'
ssh -i $HOME/.ssh/key.pem "$user"@"$ip" 'wget https://raw.githubusercontent.com/mzet-/z-field-manual/master/scripts/nobserver.sh; wget https://bitbucket.org/memoryresident/gnxtools/raw/fde3449ff2756686e001ac4f7a45849a187f3710/gnxparse.py; chmod +x nobserver.sh; chmod +x gnxparse.py'
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

### preparation: hardening

```
TODO
```
