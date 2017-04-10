**OpenAAA**, Open Source Authentication, Authorization and Accouting library

| Branch     | Status             | Binaries                 | Packages       |
|------------|--------------------|--------------------------|----------------|
| master     | [![Build Status](https://travis-ci.org/n13l/openaaa.png?branch=master)](https://travis-ci.org/n13l/openaaa) [![Build Status](https://snap-ci.com/n13l/openaaa/branch/master/build_image)](https://snap-ci.com/n13l/openaaa/branch/master) | [![Release](https://img.shields.io/github/release/n13l/openaaa.svg)](https://github.com/n13l/openaaa/releases/latest) | [![Release](https://img.shields.io/github/release/n13l/openaaa.svg)](https://packagecloud.io/n13l/openaaa) |

**Authentication**
 - strong mutual authentication using transport layer security
 - channel binding based on standard and well-defined mechanisms
 - upper layers authentication based on keying material exporters [RFC-5705]
 - anonymous authentication, no personal data transfered over channel
 - no user-credential-related risks

**Accounting**
 - binding authenticated user context to encrypted session
 - session management attributes and operation tied to secure TLS session
 - secure session negotiations and session resumption based on TLS
 - no more cookies and other state information on application layer
 - multipple network and/or application layers access same encrypted session 
 - straightforward bindings to application layer using well-defined mechanism.
 - distributed, high performance and secure session manager (aaad) daemon

**Authorization**
 - unlimited aditional authorization rules based on authenticated user context
 - multipple network and/or application layers access and share same user context

**Interoperability**
 - no additional code on top of popular crypto libraries (openssl, nss, ...)
 - platform and language independence
 - (SSO) Single sign-on

**TLS side channel authentication**
 - straightforward bindings to application layer using well-defined mechanism.
 - equivalent security as hardware-tokens
 - strong mutual authentication without trusted certificates

**TLS qualities and various attack mitigations features:**
 - cipher negotiations
 - session negotiations and session resumption
 - safe renegotiations 
 - strong authentication
 - cryptographic integrity
 - confidentiality
 - channel binding using secure channel protocols

>Besides AAA on application layer is allways prone to many implementation errors compared to TLS.
 
**URL References**

| ID              | URI                                                       |
|-----------------|-----------------------------------------------------------|
| AAA-TLS-SCA     | https://github.com/n13l/openaaa/blob/master/doc/tls-sca   |
| OPENVPN-RFC5705 | https://github.com/OpenVPN/openvpn/blob/master/doc/keying-material-exporter.txt |

