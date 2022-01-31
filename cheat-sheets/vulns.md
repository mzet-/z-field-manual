
# What goes wrong in software: Web-based applications

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

## Possible architecture flaws

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

## Burp Suite

```
# General usage:
https://portswigger.net/blog/7-burp-suite-professional-exclusive-features-to-help-you-test-smarter
https://portswigger.net/burp/pro/video-tutorials
https://portswigger.net/solutions/penetration-testing/penetration-testing-tools

# File upload scanner:
https://github.com/portswigger/upload-scanner
```

## Burp Suite Scanner

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
https://portswigger.net/blog/introducing-dom-invader
https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
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

## Open redirect

```
typical scenario (affected parameter needs to be in GET to use it as a phising vector):
https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/preventing-open-redirection-attacks

https://0xnanda.github.io/Open-Redirects-Everything-That-You-Should-Know/

https://security.stackexchange.com/questions/42168/exploiting-an-open-redirect-in-post-body

https://devcraft.io/2020/10/19/github-gist-account-takeover.html
```