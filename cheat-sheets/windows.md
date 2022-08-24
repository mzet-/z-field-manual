
## Essential commands

### System Info Commands

```
# get system version
ver
tasklist
systeminfo
# show services
sc query state=all
```

### net/domain commands

```
# get your privileges
whoami /priv
net user <user> /domain

# add user
net user <user> <passwd> /add
# add <user> to admins group
net localgroup "Administrators" <user> /add
```

### utility commands

```
# local user manager
lusrmgr.msc
# services control panel
services.msc
# security policy manager
secpool.msc
taskmgr.exe
eventvwr.msc
# show permissions for chosen exe file
icacls <exe>
```

## cmd.exe

## Powershell

### PowerSploit - offensive capabilities library

    https://github.com/PowerShellMafia/PowerSploit


## Sysinternals

    https://docs.microsoft.com/en-us/sysinternals/

## Reference

```
https://book.hacktricks.xyz/windows-hardening/basic-cmd-for-pentesters
```
