
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
             - [SMB](Lateral%20Movement/lm-flawed-services.md#smb-service)
             - [RDP](Lateral%20Movement/lm-flawed-services.md#rdp-service)
             - [MS-SQL](Lateral%20Movement/lm-flawed-services.md#ms-sql-service)
             - [WinRM](Lateral%20Movement/lm-flawed-services.md#winrm)
             - [Other Windows services](Lateral%20Movement/lm-flawed-services.md#other-windows-services)
             - [SNMP](Lateral%20Movement/lm-flawed-services.md#snmp-service)
             - [SMTP](Lateral%20Movement/lm-flawed-services.md#smtp-service)
             - [NTP](Lateral%20Movement/lm-flawed-services.md#ntp-service)
         - Flawed HTTP/HTTPS Remote Services
             - [Apache Tomcat: default/weak credentials](#apache-tomcat-defaultweak-credentials)
         - Flawed embedded devices
         - Feature Abuse
    - Escalate

<!-- /MarkdownTOC -->

# Expanding Influence
