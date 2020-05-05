
## Reference

```
# OWASP API Security Top 10
https://owasp.org/www-project-api-security/

# OWASP REST Security cheat sheet
https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
```

## Some ideas/references/test cases

### External resources

[Security testing for REST applications](http://www.slideshare.net/SOURCEConference/security-testing-for-rest-applications-ofer-shezaf-source-barcelona-nov-2011)

[OWASP cheat sheet](https://www.owasp.org/index.php/Testing_for_Web_Services)

[REST API security testing](https://github.com/pwntester/RSA_RESTing/tree/master/Presentation)

Interesting REST API fuzzer:

```
https://github.com/Fuzzapi/fuzzapi
```

### Test manually with Burp

Zastosuj podejscie jak do aplikacji web'owej i uzyj maksymalnie duzo test case'ow, ktore maja tu sens, np:

 - Authn/Authz
 - Use burp sequencer to test randomness of tokens

### Check reality with documentation

Perform requests to all supported functions and methods and make sure that:

 - each function only allows methods as in doc
 - for functions that support POST and PUT: data syntax is validated (e.g. json syntax)
 - for functions that support POST and PUT: json/xml schema is validated 
 - for functions that support POST and PUT: json/xml fields are validated

### Error handling

Verify if consistent way to report errors is used in whole system.

### Custom fuzzer

Consider writing custom fuzzer for given web service functions use Sulley, Peach or just Python script.

### Looking for API key leaks

    https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks

### Input validation testing

Burp + Postman + w3af

```
https://blog.gypsyengineer.com/en/security/security-testing-for-rest-api-with-w3af.html
https://github.com/Yelp/bravado-core
https://portswigger.net/bappstore/6ae9ede3630949748842a43518e840a7
```
