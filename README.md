scala-ldap-server
===================

[![Known Vulnerabilities](https://snyk.io/test/github/rleibman/scala-ldap-server/badge.svg)](https://snyk.io/test/github/rleibman/scala-ldap-server)

An ldap server developed in Scala. It uses akka

##Install

I'd like to use sbt-native-packager to deliver this at least into deb and rpm systems, but probably msi and dmg as well.

##Changelog

See [changelog](./CHANGELOG.md)

##Features

##Usage

## Contributing

Use [Github issues](https://github.com/rleibman/scala-ldap-server/issues) for feature requests and bug reports.

We actively welcome pull requests.

For setting up & starting the project locally:
You will need an instance of mongo running, and you'll have to tweak application.conf to suit your environment

Once you have all that, use:

```sh
$ git clone https://github.com/rleibman/scala-ldap-server
$ cd scala-ldap-server
$ sbt run
cd -
```

## License

#### [GPL](./LICENSE)

## Developers
So, this project is mostly a way for me to vent, practice and try some new stuff and technologies as it comes. 
Upon looking at it, it's much more complicated than I first thought. So unless someone else is interested in it and 
wants to help along I'll likely never get it to the point of actually working.
Please let me know if you're interested in helping.
I'm using the following documents to implement the server

### Lightweight Directory Access Protocol (LDAP)
#### Basic documents 
- [rfc4510](https://tools.ietf.org/html/rfc4510) Technical Specification Road Map 
- [rfc4511](https://tools.ietf.org/html/rfc4511) The Protocol 
- [rfc4512](https://tools.ietf.org/html/rfc4512) Directory Information Models 
- [rfc4513](https://tools.ietf.org/html/rfc4513) Authentication Methods and Security Mechanisms 
- [rfc4514](https://tools.ietf.org/html/rfc4514) String Representation of Distinguished Names 
- [rfc4515](https://tools.ietf.org/html/rfc4515) String Representation of Search Filters 
- [rfc4516](https://tools.ietf.org/html/rfc4516) Uniform Resource Locator 
- [rfc4517](https://tools.ietf.org/html/rfc4517) Syntaxes and Matching Rules 
- [rfc4518](https://tools.ietf.org/html/rfc4518) Internationalized String Preparation 
- [rfc4519](https://tools.ietf.org/html/rfc4519) Schema for User Applications
 
#### Some Extras
- [rfc4520](https://tools.ietf.org/html/rfc4520) Internet Assigned Numbers Authority (IANA) Considerations for the Lightweight Directory Access Protocol (LDAP) 
- [rfc4521](https://tools.ietf.org/html/rfc4521) Considerations for Lightweight Directory Access Protocol (LDAP) Extensions 
- [rfc4522](https://tools.ietf.org/html/rfc4522) The Binary Encoding Option 
- [rfc4523](https://tools.ietf.org/html/rfc4523) Schema Definitions for X.509 Certificates 
- [rfc4524](https://tools.ietf.org/html/rfc4524) COSINE LDAP/X.500 Schema 
- [rfc4525](https://tools.ietf.org/html/rfc4525) Modify-Increment Extension 
- [rfc4526](https://tools.ietf.org/html/rfc4526) Absolute True and False Filters 
- [rfc4527](https://tools.ietf.org/html/rfc4527) Read Entry Controls 
- [rfc4528](https://tools.ietf.org/html/rfc4528) Assertion Control 
- [rfc4529](https://tools.ietf.org/html/rfc4529) Requesting Attributes by Object Class in the Lightweight Directory Access Protocol (LDAP) 
- [rfc4530](https://tools.ietf.org/html/rfc4530) entryUUID Operational Attribute 
- [rfc4531](https://tools.ietf.org/html/rfc4531) Turn Operation 
- [rfc4532](https://tools.ietf.org/html/rfc4532) "Who am I?" Operation 
- [rfc4533](https://tools.ietf.org/html/rfc4533) Content Synchronization Operation

#### Oids
- [Oid reference](https://www.ldap.com/ldap-oid-reference) oid's that may be returned from the base in supportedControl, supportedExtension, supportedFeatures
- [Another oid reference](http://www.networksorcery.com/enp/protocol/ldap.htm)

OpenLDAP supports the following on a bare bones system

##### SupportedControl
- 2.16.840.1.113730.3.4.18 Proxied Authorization v2 Request Control (RFC 4370)
- 2.16.840.1.113730.3.4.2  ManageDsaIT Request Control (RFC 3296)
- 1.3.6.1.4.1.4203.1.10.1  Subentries (RFC 3672)
- 1.2.840.113556.1.4.319   Simple Paged Results Control (RFC 2696)
- 1.2.826.0.1.3344810.2.3  Matched Values Request Control (RFC 3876)
- 1.3.6.1.1.13.2           Post-Read Request and Response Controls (RFC 4527)
- 1.3.6.1.1.13.1           Pre-Read Request and Response Controls (RFC 4527)
- 1.3.6.1.1.12             Assertion Request Control (RFC 4528)
- 1.3.6.1.4.1.1466.20037   StartTLS Request (RFC 4511)

##### supportedExtension
- 1.3.6.1.4.1.4203.1.11.1  Password ModifY Request (RFC 3062)
- 1.3.6.1.4.1.4203.1.11.3  "Who Am I?" Request (RFC 4532)
- 1.3.6.1.1.8              Cancel Request (RFC 3909)

##### supportedFeatures
- 1.3.6.1.1.14             Modify-Increment. (RFC 4525)
- 1.3.6.1.4.1.4203.1.5.1   All Operational Attributes. (RFC 3673)
- 1.3.6.1.4.1.4203.1.5.2   OC AD Lists (RFC 4529)
- 1.3.6.1.4.1.4203.1.5.3   True/False Filters (RFC 4526)
- 1.3.6.1.4.1.4203.1.5.4   Language tags options (RFC 3866)
- 1.3.6.1.4.1.4203.1.5.5   Language range options (RFC 3866)

### Anonymous Simple Authentication and Security Layer (SASL) Mechanism
- [rfc4505](https://tools.ietf.org/html/rfc4505) Technical Specification Road Map 

https://www.ldap.com/ldap-specifications-defined-in-rfcs

I'm also making heavy use of the Apache Directory Studio to test the server, as well as of the openldap tools (ldapsearch, etc)
