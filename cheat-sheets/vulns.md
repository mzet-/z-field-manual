
# What goes wrong

## Possible consequences

```
- RCE (popping a shell)
- application account takeover
- access to functionality of other (preferably more privileged) user
- exfil of data belonging to other (preferably more privileged) user
- abuse existing (accessible) functionality
- attacks on clients
- DoS (optionally)
- attacks on maintainers (optionally)
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

## SQLi
