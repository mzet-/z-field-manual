
<!-- MarkdownTOC depth=3 autolink=true -->

- [Expanding Influence](#expanding-influence)
    - Credential Access (TA0006)
        - MitM (T1557)
            - [LLMNR/mDNS/NBNS poisonning and SMB relay](Credential%20Access/ca-1.md) (T1557.001)
            - [DNS Poisoning via DHCPv6 and SMB Relay](Credential%20Access/ca-2.md)
            - [ARP + DNS Poisoning and SMB Relay](Credential%20Access/ca-3.md)
    - Move Laterally
         - [Flawed Network Equipment](#flawed-network-equipment)
         - [Flawed Remote Services](#flawed-remote-services) (T1210)
             - [SMB](#smb-service)
             - [RDP](#rdp-service)
             - [MS-SQL](#ms-sql-service)
             - [WinRM](#winrm)
             - [Other Windows services](#other-windows-services)
             - [SNMP](#snmp-service)
             - [SMTP](#smtp-service)
             - [NTP](#ntp-service)
         - [Flawed HTTP/HTTPS Remote Services](#flawed-httphttps-remote-services)
             - [Apache Tomcat: default/weak credentials](#apache-tomcat-defaultweak-credentials)
         - [Flawed embedded devices](#flawed-embedded-devices)
         - Feature Abuse
    - Escalate

<!-- /MarkdownTOC -->

# Expanding Influence
