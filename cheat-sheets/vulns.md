
# What goes wrong in software: Web-based applications

<!-- MarkdownTOC depth=3 autolink=true -->

- [Abstract model of the target](#abstract-model-of-the-target)
- Possible consequences (goals)
- Inspiration
- Possible architectural flaws
- Know your toolbox: Burp Suite Scanner
- Know your toolbox: API Testing
- Know your toolbox: Burp Suite tips and tricks
- Recon

Server-side issues:

- Account takeover(#account-takeover)
- Authentication and session mgmt
- Authorization
- SQLi
- Directory traversal / file read
- File inclusions
- Open redirects
- [XXE](#xxe)
- [Server misconfigurations](#server-misconfigurations)
- [JWT](#jwt)

Issues on transit:

- SSRF
- [HTTP Host header attacks](#http-host-header-attacks)

Client-side issues:

- [XSS](#xss)
- [DOM issues](#dom-issues)

<!-- /MarkdownTOC -->

## Abstract model of the target

*System is secure if it does what it should and nothing more*

    ARCHITECTURE | IMPLEMENTATION | INFRASTRUCTURE:

    - application (client | transit | backend)
    - internal network
    - cloud environment
    - external 3rd party web resources

	OPS:

    - application/infrastructure management mechanisms

Optionally to consider in the model:

	IMPLEMENTATION:

    - low-level native code used (e.g. for parsing) on the backend

## Possible consequences

Holly Grail:

```
RCE (popping a shell)
https://rosettacode.org/wiki/Execute_a_system_command
```

Other:

```
- application account takeover
- access to functionality of other (preferably more privileged) user
- exfil of data belonging to other (preferably more privileged) user
- abuse existing (accessible) functionality
- attacks on clients
- DoS (optionally)
- attacks on maintainers (optionally)
```

More:

```
https://portswigger.net/kb/issues
```

## Inspiration

```
https://www.agarri.fr/blog/archives/2021/04/23/a_recap_of_the_q_ampa_session_on_twitter/index.html
```

## Possible architectural flaws

```
Can you identify arch type: internal | zero-trust style | hybrid
What application stack is being used?
What platform / infrastructure is being used?
Where crypto is used? For what purpose?
What authn mechanism is used?
How session is maintained?
What roles/user privileges are there (is horizontal and/or vertical separation is present)?
Any other security critical functionality (search, file uploads, payments, ...)?
Websockets are used?
How can you characterize UI (standard / "one|few page style" / flash / thick)?
Is a web service (REST / SOAP) present?
```

## Burp Suite: Misc

```
# General usage:
https://portswigger.net/blog/7-burp-suite-professional-exclusive-features-to-help-you-test-smarter
https://portswigger.net/burp/pro/video-tutorials
https://portswigger.net/solutions/penetration-testing/penetration-testing-tools

# File upload scanner:
https://github.com/portswigger/upload-scanner
```

## Burp Suite: Scanner

```
# Scanner usage tips & tricks:
https://portswigger.net/web-security/reference/augmenting-your-manual-testing-with-burp-scanner

# Active scanner's essential extensions:
https://github.com/portswigger/scan-manual-insertion-point
https://github.com/portswigger/backslash-powered-scanner
https://github.com/portswigger/j2ee-scan

# Passive scanner's essential extensions:
https://github.com/portswigger/retire-js
```

## API Testing

```
https://portswigger.net/blog/api-scanning-with-burp-suite
```

## Recon

```
Objectives:
target enumeration
mapping application
understanding application (triad: functionality; technology; data entry points)

# Crawling:
https://portswigger.net/blog/browser-powered-scanning-in-burp-suite
```

## Account takeover

Cases of account takeover (via forgot password functionality):

```
https://thezerohack.com/how-i-might-have-hacked-any-microsoft-account
https://infosecwriteups.com/unauthenticated-account-takeover-through-forget-password-c120b4c1141d
https://www.pentagrid.ch/en/blog/password-reset-code-brute-force-vulnerability-in-AWS-Cognito/
https://blog.assetnote.io/2021/06/27/uber-account-takeover-voicemail/
https://infosecwriteups.com/account-takeovers-believe-the-unbelievable-bb98a0c251a4
https://sekurak.pl/jak-czasem-mozna-latwo-oszukac-mechanizm-przypominania-hasla-vulnz/
```

## Authentication and session mgmt

Handy Burp extensions:

```
# Session handling via HTTP header:
https://github.com/portswigger/add-custom-header

# JWT:
https://github.com/portswigger/json-web-tokens
https://github.com/portswigger/json-web-token-attacker
```

## Authorization

## XSS

```
# Web Technology for developers:
https://developer.mozilla.org/en-US/docs/Web

https://portswigger.net/web-security/cross-site-scripting
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

# More about DOM-based XSSes:
https://portswigger.net/web-security/cross-site-scripting/dom-based
https://portswigger.net/blog/introducing-dom-invader

# Investigating:
https://security.stackexchange.com/questions/256268/xss-in-span-where-only-and-are-encoded
```

## SQLi

```
TODO
```

## Directory traversal / file read

```
https://portswigger.net/web-security/file-path-traversal
https://afinepl.medium.com/practical-strategies-for-exploiting-file-read-vulnerabilities-272abe792078
```

## File inclusions

```
LFI/RFI
```

## Open redirects

```
typical scenario (affected parameter needs to be in GET to use it as a phising vector):
https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/preventing-open-redirection-attacks

https://0xnanda.github.io/Open-Redirects-Everything-That-You-Should-Know/

https://security.stackexchange.com/questions/42168/exploiting-an-open-redirect-in-post-body

https://devcraft.io/2020/10/19/github-gist-account-takeover.html
```

## XXE

```
# Payloads:
https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html
https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/xxe.md
```

## HTTP Host header attacks

Reference:

    https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
    https://portswigger.net/web-security/host-header
    https://portswigger.net/web-security/host-header/exploiting

Problems:

## DOM issues

Reference:

    https://portswigger.net/web-security/dom-based
    https://portswigger.net/web-security/dom-based/dom-clobbering
    https://bughunters.google.com/learn/presentations/4899501820870656

Issues:

Drills:

    https://portswigger.net/web-security/all-labs#dom-based-vulnerabilities

## SSRF

Reference:

    https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf

## Server misconfigurations

```
# HTTP 403 Forbidden Bypass
https://hackerone.com/reports/991717

# Cloudflare bypass
https://hackerone.com/reports/360825
```

## JWT

Attacking JWT:

```
https://mazinahmed.net/blog/breaking-jwt/
https://research.securitum.com/jwt-json-web-token-security/
https://github.com/ticarpi/jwt_tool/wiki
https://www.nccgroup.com/ae/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/
```

Cracking JWT:

```
(put JWT token in jwt.txt)
./hashcat-5.1.0/hashcat -m 16500 PrimePhoenix/jwt.txt wordlists/Top2Billion-probable-v2.txt -O
For more see:
https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology#weak-hmac-secret-used-as-a-key
```
