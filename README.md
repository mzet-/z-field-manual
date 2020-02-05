# Security Testing Field Manual

Introduction and purpose.

# Operational Considerations

## Goals

List of possible goals.

## Operation Planning

```
1. Set goal(s): objectives to accomplish
2. Combine various tactics to achieve your operational goal(s)
3. Select appropriate tachniques (and choose suitable tools) to achieve your tactical goals
```

## Toolbox

# Tactical Objectives

## Ops-Sec Considerations ([PRE-ATT&CK: TA0021](https://attack.mitre.org/tactics/TA0021/))

## Attack Infrastructure ([PRE-ATT&CK: TA0022](https://attack.mitre.org/tactics/TA0022/))

## Getting internal IP address ([ATT&CK: TA0001](https://attack.mitre.org/tactics/TA0001/))

*Tactical goal: get IP address in target's internal network*

Possible techniques to use (in a form of attack tree):

```
1. [OR] Social Engineering
1.1. [OR] Delivery of phishing email/message
1.1.1. Malicious link (T1192)
1.1.2. Malicious attachment (T1193)
1.1.3. Malicious social media message (T1194)
1.2. Drive-by compromise (T1189)
1.3. [OR] "Tasking" insider to plant connect-back implant
1.3.1. by fooling him (e.g. run it for me; print doc from this USB)
1.3.2. by bribing him
1.3.3. by blackmailing him
1.4. Fooling insider to reveal his credentials (T1078)
...

2. Breaching the perimeter/DMZ
2.1. Exploit Public-Facing Application (T1190)
2.2. Exploit remote access mechanism (T1133)
...

3. Proximity attacks
3.1. Hacking into wireless network
3.2. Using USB drive drops (T1091)
3.3. [OR] Breaching physical perimeter
3.3.1. Plant drop-in device and plug it into network
3.3.2. Plant USB device and plug it to existing machine
...

4. [OR] Exploiting Trusted Relationship (T1199)
4.1. Hack 3rd party entity that delivers service to target (T1195)
4.1.1. Open source Software supplier 
4.1.2. Commercial Software supplier 
4.1.3. Hack company that provides services to the target
4.1.4. Hack target's contractor worker
4.2. [AND] Hack "to be acquired" company
4.2.1. Get knowledge about near aquisitions
4.2.1. Hack the company that is going to be acquired 
4.3. [AND] Build trust relationship with the target
4.3.1. Work as a contractor for the target
4.3.2. Exploit the trust that was built
...
```

## Internal recon ([ATT&CK: TA0007](https://attack.mitre.org/tactics/TA0001/))

## Credential Access ([ATT&CK: TA0006](https://attack.mitre.org/tactics/TA0001/))

## Lateral Movement ([ATT&CK: TA0008](https://attack.mitre.org/tactics/TA0001/))
