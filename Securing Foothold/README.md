
<!-- MarkdownTOC depth=3 autolink=true -->

- [Securing Foothold](#securing-foothold)
    - Persist (TA0003)
        - Account Manipulation (T1098)
            - DC Skeleton Key
        - Hijack Execution Flow (T1574)
            - Custom SSP for Windows
        - Valid Accounts (T1078)
            - Default Accounts (T1078.001)
                - DC Administrator account with DSRM password
            - Domain Accounts (T1078.002)
                - krbtgt account (golden ticket)
                - service account (silver ticket)
        - Feature Abuse
            - Windows AD ACL abuse
                - AdminSDHolder ACL manipulation
                - Adding DCSync rights to Domain object
    - C2 (TA0011)

<!-- /MarkdownTOC -->

# Securing Foothold
