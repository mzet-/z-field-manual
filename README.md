
# CNE Field Manual

Computer Network Exploitation Field Guide

Introduction and purpose of this guide.

## Glossary

For the purpose of this publication following terms are used:

CNE - Computer Network Exploitation. Term adopted from US DoD. Types of enabling operations and intelligence collection capabilities conducted through the use of computer networks to gather data from target or adversary information systems or networks.

Field manual - term adopted from US Military. Field manuals contain detailed information and how-tos for procedures important to soldiers serving in the field.

Z Field manual - field manual developed and maintained by [Z-Labs](https://z-labs.eu) that contains detailed information and how-tos for precedures important to red team operators / penetration testers serving / working in the field of cyber security.

Attack trees -

Attack graphs -

Kill Chain -

Tactic - 

TTP -

[MITRE ATT&CK](https://attack.mitre.org/) -

[NSA/CSS Cyber Threat Framework](https://www.dni.gov/index.php/cyber-threat-framework) -

TIBER EU -

# Strategic Assumptions

On strategical level we're usually communicating with the stakeholders (e.g. organization's executives) regarding **cyber security** in terms of a **risk**.

    Risk = threats x vulnerabilities x assets

Conceptually breaking down red teaming process:

1. We study the behavior of known cyber threat actors to understand the threats they colud pose.
2. We study the customer's environment (people, processes, technology) to understand under what threat model they operate.
3. We analyze, adapt, refine and design the TTPs (tactics, techniques, procedures) that could be used by our customer's adversaries.
4. We develop and run adversarial operations to simulate highly probable, sophisticated and realistic attacks tailored for the target organization.

# Operational Considerations


## Operation Planning

```
1. Identify biggest risks for your target
2. Set goal(s): objectives to accomplish based on identified risks
```

## Goals

List of typical goals (typically affecting victim's data CIA triad):

[Goals](Goals/README.md)

## Operation Preparation

```
1. Consider level of OPS-SEC required
2. Preapre attack infrastructure
3. Launch an operation
```

## Running an Operation

```
1. Determine a set of tactical objectives required to achieve your operational goal(s)
2. Achieve required tactical objective(s)
3. Choose feasible technique(s) to achieve given tactical objective
```

# Tactical Objectives

## Intelligence Gathering

Collection of discovery techniques and associated procedures commonly used during various stages of intrusion lifecycle.

[OSINT Discovery](Intelligence%20Gathering/README.md)

[Network Discovery](Discovery/README.md)

[Active Directory (AD) Discovery](Discovery/discovery-ad.md)

[ Cloud Discovery ]

Services Discovery: [HTTP-based](Discovery/discovery-http-services.md) | [All other](Discovery/discovery-services.md)

## Getting Foothold

Repository of techniques and associated procedures (in a form of attack trees) used for gaining initial foothold in target network environment.

[Getting Inside Attack Tree](Getting%20Inside/README.md)

Attack (sub) trees:

TODO

## Expanding Influence

Repository of techniques and associated procedures (in a form of attack trees) used for accomplishing operational goals in target network environment.

[Expanding Influence Attack Tree](Expand%20Influence/README.md)

Attack (sub) trees:

[ Escalating Windows domain privileges ]

[ Window host privilege escalation ]

[ Linux/UNIX host privilege escalation ]

## Survivability

Collection of techniques and associated procedures (from following categories: Persistence, C2, Evasion) used to support and maintain undisturbed operation workflow.

[Securing Foothold](Securing%20Foothold/README.md)

## Cheat Sheets

[ What goes wrong in software: Native applications ]

[What goes wrong in software: Web-based applications](cheat-sheets/vulns.md)

[Known RCE collection](cheat-sheets/rce-collection.md)

Command line fu: [ oneliners ] | [ UNIX cli ] | [Windows cli](cheat-sheets/windows.md)

[Scripting building blocks](cheat-sheets/scripting.md)

[Payloads](res/README.md)

[ Network pivoting ]

[SSH](cheat-sheets/ssh.md)

[Metasploit](cheat-sheets/metasploit.md)

 - [Red team infrastructure](cheat-sheets/testing-infra.md)
     - [Arch Linux](cheat-sheets/arch.md)
     - [Service deployments](cheat-sheets/http-srv.md)


## Toolbox: custom implemented tools

```
TODO
```

## Toolbox: 3rd party tools

Shortcuts:

```
https://github.com/projectdiscovery/uncover/releases/latest
https://github.com/zmap/zmap/releases/latest
https://github.com/zmap/zgrab2/releases/latest

https://github.com/projectdiscovery/httpx/releases/latest
https://github.com/michenriksen/aquatone/releases/latest

https://github.com/ffuf/ffuf/releases/latest
https://github.com/OJ/gobuster/releases/latest

https://github.com/tomnomnom/meg/releases/latest
https://github.com/projectdiscovery/nuclei/releases/latest

https://github.com/zmap/zannotate
```

### snallygaster

About:

Looks for secret files on HTTP servers.

Get:

    wget https://raw.githubusercontent.com/hannob/snallygaster/main/snallygaster

### weak_passwords

About:

Generates set of typical passwords based on provided word (e.g. company name).

Get:

    wget https://raw.githubusercontent.com/averagesecurityguy/scripts/master/passwords/weak_passwords.py

### namemash

About:

Generates combinations of username based on privided name and surname tuples.

Get:

    wget https://gist.githubusercontent.com/superkojiman/11076951/raw/74f3de7740acb197ecfa8340d07d3926a95e5d46/namemash.py
