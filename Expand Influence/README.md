
<!-- MarkdownTOC depth=3 autolink=true -->

- [Expanding Influence](#expanding-influence)
    - Credential Access (TA0006)
        - MitM (T1557)
            - [LLMNR/mDNS/NBNS poisonning and SMB relay](Credential%20Access/ca-1.md) (T1557.001)
            - [DNS Poisoning via DHCPv6 and SMB Relay](Credential%20Access/ca-2.md)
            - [ARP + DNS Poisoning and SMB Relay](Credential%20Access/ca-3.md)
    - Move Laterally
         - [Flawed Network Equipment](Lateral%20Movement/lm-flawed-network-equipment.md)
         - [Flawed Remote Services](Lateral%20Movement/lm-flawed-services.md) (T1210)
             - [SMB](Lateral%20Movement/lm-flawed-services.md#smb-service)
             - [RDP](Lateral%20Movement/lm-flawed-services.md#rdp-service)
             - [MS-SQL](Lateral%20Movement/lm-flawed-services.md#ms-sql-service)
             - [WinRM](Lateral%20Movement/lm-flawed-services.md#winrm)
             - [Other Windows services](Lateral%20Movement/lm-flawed-services.md#other-windows-services)
             - [SNMP](Lateral%20Movement/lm-flawed-services.md#snmp-service)
             - [SMTP](Lateral%20Movement/lm-flawed-services.md#smtp-service)
             - [VoIP protocol suite](Lateral%20Movement/lm-flawed-services.md#voip-protocol-suite)
             - [NoSQL services](Lateral%20Movement/lm-flawed-services.md#nosql-services)
             - [Network storage/backup services](Lateral%20Movement/lm-flawed-services.md#network-storagebackup-services)
             - [VoIP protocol suite](Lateral%20Movement/lm-flawed-services.md#voip-protocol-suite)
             - [NTP](Lateral%20Movement/lm-flawed-services.md#ntp-service)
             - [NTP](Lateral%20Movement/lm-flawed-services.md#legacy-remote-shells)
         - [Flawed HTTP Remote Services](Lateral%20Movement/lm-flawed-http-services.md)
             - [Apache Tomcat: default/weak credentials](Lateral%20Movement/lm-flawed-http-services.md#apache-tomcat-defaultweak-credentials)
         - Flawed embedded devices
         - Feature Abuse
    - Escalate

<!-- /MarkdownTOC -->

# Expanding Influence

Repository of techniques and associated procedures for expanding the influence in target network environment.
