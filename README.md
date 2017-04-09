**OpenAAA**, Open Source Authentication, Authorization and Accouting library

| Branch     | Status             | Binaries                 | Packages       |
|------------|--------------------|--------------------------|----------------|
| master     | [![Build Status](https://travis-ci.org/n13l/openaaa.png?branch=master)](https://travis-ci.org/n13l/openaaa) [![Build Status](https://snap-ci.com/n13l/openaaa/branch/master/build_image)](https://snap-ci.com/n13l/openaaa/branch/master) | [![Release](https://img.shields.io/github/release/n13l/openaaa.svg)](https://github.com/n13l/openaaa/releases/latest) | [![Release](https://img.shields.io/github/release/n13l/openaaa.svg)](https://packagecloud.io/n13l/openaaa) |

**Authentication**
 - strong authentication based on TLS
 - anonymous authentication, no personal data transfered over channel
 - no user-credential-related risks

**Accounting**
 - binding authenticated user context to encrypted session
 - session management attributes and operation tied to secure TLS session
 - no more http cookies and other state information on application layer
 - multipple network and/or application layers access same encrypted session 
 - straightforward bindings to application layer using well-defined mechanism.

**Authorization**
 - unlimited aditional authorization rules based on authenticated user context

**Interoperability**
 - no additional code on top of popular crypto libraries (openssl, nss, ...)

**TLS side channel authentication**

TLS side channel authentication and straightforward bindings of AAA information
to application layer using well-defined mechanism.

**TLS qualities and various attack mitigations features:**
 - cipher negotiations
 - session negotiations and session resumption
 - safe renegotiations 
 - strong authentication
 - cryptographic integrity
 - confidentiality
 - channel binding using secure channel protocols

>Besides authentication and accounting on application layer is allways prone to many 
attacks and implementation errors compared to TLS.
 
**URL References**

| ID              | URI                                                       |
|-----------------|-----------------------------------------------------------|
| AAA-TLS-SCA     | https://github.com/n13l/openaaa/blob/master/doc/tls-sca   |
| OPENVPN-RFC5705 | https://github.com/OpenVPN/openvpn/blob/master/doc/keying-material-exporter.txt |

