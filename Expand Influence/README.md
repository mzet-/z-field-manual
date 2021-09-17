
<!-- MarkdownTOC depth=3 autolink=true -->

- [Expanding Influence](#expanding-influence)
    - Credential Access (TA0006)
        - MitM (T1557)
            - [LLMNR/mDNS/NBNS poisonning and SMB relay](Credential%20Access/ca-1.md) (T1557.001)
            - [DNS Poisoning via DHCPv6 and SMB Relay](Credential%20Access/ca-2.md)
            - [ARP + DNS Poisoning and SMB Relay](Credential%20Access/ca-3.md)
            - [SSDP/UPNP and SMB Relay](Credential%20Access/ca-4.md)
    - Lateral Movement (TA0008)
         - [Flawed Network Equipment](Lateral%20Movement/lm-flawed-network-equipment.md)
         - [Flawed Windows-based Services](Lateral%20Movement/lm-flawed-services.md) (T1210)
             - [SMB](Lateral%20Movement/lm-flawed-services.md#smb-service)
             - [RDP](Lateral%20Movement/lm-flawed-services.md#rdp-service)
             - [MS-SQL](Lateral%20Movement/lm-flawed-services.md#ms-sql-service)
             - [WinRM](Lateral%20Movement/lm-flawed-services.md#winrm)
             - [Windows Kerberos](Lateral%20Movement/lm-flawed-services.md#windowskerberos)
             - [Other Windows services](Lateral%20Movement/lm-flawed-services.md#other-windows-services)
         - [Flawed Services](Lateral%20Movement/lm-flawed-services.md) (T1210)
             - [SNMP](Lateral%20Movement/lm-flawed-services.md#snmp-service)
             - [SMTP](Lateral%20Movement/lm-flawed-services.md#smtp-service)
             - [VoIP protocol suite](Lateral%20Movement/lm-flawed-services.md#voip-protocol-suite)
             - [NoSQL services](Lateral%20Movement/lm-flawed-services.md#nosql-services)
             - [Network storage/backup services](Lateral%20Movement/lm-flawed-services.md#network-storagebackup-services)
             - [VoIP protocol suite](Lateral%20Movement/lm-flawed-services.md#voip-protocol-suite)
             - [NTP](Lateral%20Movement/lm-flawed-services.md#ntp-service)
             - [SSH](Lateral%20Movement/lm-flawed-services.md#ssh)
             - [Legacy remote shells](Lateral%20Movement/lm-flawed-services.md#legacy-remote-shells)
             - [BMC/IPMI](Lateral%20Movement/lm-flawed-services.md#bmcipmi)
             - [Printers](Lateral%20Movement/lm-flawed-services.md#printers)
             - [Java-based services](Lateral%20Movement/lm-flawed-services.md#java-based-services)
             - [VNC services](Lateral%20Movement/lm-flawed-services.md#vnc)
             - [Oracle DBs](Lateral%20Movement/lm-flawed-services.md#oracle)
         - [Flawed HTTP Services](Lateral%20Movement/lm-flawed-http-services.md)
             - [Generic web vulnerability discovery](Lateral%20Movement/lm-flawed-http-services.md#web-vulnerability-discovery)
             - [Web-based authentication panels](Lateral%20Movement/lm-flawed-http-services.md#web-based-authentication-panels)
             - [Apache Tomcat: default/weak credentials](Lateral%20Movement/lm-flawed-http-services.md#apache-tomcat-defaultweak-credentials)
             - COTS web apps
                - [Wordpress](Lateral%20Movement/lm-flawed-http-services.md#wordpress)
                - [Atlassian Confluence](Lateral%20Movement/lm-flawed-http-services.md#atlassian-confluence)
                - Jira
         - [Flawed Technology](Lateral%20Movement/lm-flawed-services.md) (T1210)
             - [VMware](Lateral%20Movement/lm-flawed-services.md#vmware)
         - Flawed embedded devices
         - Feature Abuse
    - Privilege Escalation (TA0004)

<!-- /MarkdownTOC -->

# Expanding Influence

Repository of techniques and associated procedures for expanding the influence in target network environment.
