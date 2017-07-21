**OpenAAA**, Open Source Authentication, Authorization and Accouting library

| Branch     | Status             | Binaries                 | Packages       |
|------------|--------------------|--------------------------|----------------|
| master     | [![Build Status](https://travis-ci.org/n13l/openaaa.png?branch=master)](https://travis-ci.org/n13l/openaaa) [![Build Status](https://snap-ci.com/n13l/openaaa/branch/master/build_image)](https://snap-ci.com/n13l/openaaa/branch/master) | [![Release](https://img.shields.io/github/release/n13l/openaaa.svg)](https://github.com/n13l/openaaa/releases/latest) | [![Release](https://img.shields.io/github/release/n13l/openaaa.svg)](https://packagecloud.io/n13l/openaaa) |

**Authentication**
 - strong mutual authentication using transport layer security
 - channel binding based on standard and well-defined mechanisms
 - upper layers authentication based on keying material exporters [RFC-5705]
 - anonymous authentication, no personal data transfered over channel
 - general extension mechanisms negotiate peers whether to use specific methods
 - supplemental data in the handshake protocol negotiating AAA methods [RFC-4680]
 - TLS re/negotiation is used as signal for the re/authentication
 - no user-credential-related risks

**Accounting**
 - binding authenticated user context to encrypted session
 - session management attributes and operation tied to secure TLS session
 - secure session negotiations and session resumption are based on TLS
 - no more cookies and other state information on application layer
 - multipple network and/or application layers access same encrypted session 
 - distributed, high performance and secure session manager (aaad) daemon
 - easy user tracking over authenticated sessions with user context
 - single point log off can destroys all authenticated sessions and invalidate crypto material

**Authorization**
 - unlimited additional upper layer authorization rules using single authenticated user context
 - multipple network and/or application layers access and share same authenticated session

**Interoperability**
 - no additional code on top of popular crypto libraries (openssl, nss, ...)
 - platform and language independence
 - (SSO) Single sign-on

**TLS side channel authentication**
 - equivalent security as hardware-tokens
 - strong mutual authentication without trusted certificates and CAs
 - straightforward bindings to application layer using well-defined mechanism.

**TLS qualities and various attack mitigations features:**
 - cipher negotiations
 - session negotiations and session resumption
 - safe renegotiations [RFC-5746]
 - application-layer protocol negotiation [RFC-7301]
 - strong authentication
 - cryptographic integrity
 - confidentiality
 - channel binding using secure channel protocols

>Besides AAA on application layer is allways prone to many implementation errors compared to TLS.

**Examples** 
 - TLS Server example: https://github.com/n13l/openaaa/blob/master/test/ssl/tls-server.sh
 - TLS Client example: https://github.com/n13l/openaaa/blob/master/test/ssl/tls-client.sh
 - HTTP2/TLS Client example: https://github.com/n13l/openaaa/blob/master/test/ssl/http2-client.sh
 - Java Client example: https://github.com/n13l/http2-pkcs11/blob/master/com/openaaa/tls/Test.java
 - Apache/2.4.25 (Unix) OpenAAA/1.0.0 OpenSSL/1.0.2k : https://aaa.rtfm.cz

**URL References**

| ID              | URI                                                       |
|-----------------|-----------------------------------------------------------|
| AAA-TLS-SCA     | https://github.com/n13l/openaaa/blob/master/doc/tls-sca   |
| OPENVPN-RFC5705 | https://github.com/OpenVPN/openvpn/blob/master/doc/keying-material-exporter.txt |

