**OpenAAA**, Open Source Authentication, Authorization and Accouting library

| Branch     | Status             | Binaries                 | Packages       |
|------------|--------------------|--------------------------|----------------|
| master     | [![Build Status](https://travis-ci.org/n13l/openaaa.png?branch=master)](https://travis-ci.org/n13l/openaaa) [![Build Status](https://snap-ci.com/n13l/openaaa/branch/master/build_image)](https://snap-ci.com/n13l/openaaa/branch/master) | [![Release](https://img.shields.io/github/release/n13l/openaaa.svg)](https://github.com/n13l/openaaa/releases/latest) | [![Release](https://img.shields.io/github/release/n13l/openaaa.svg)](https://packagecloud.io/n13l/openaaa) |


              TLS side channel authentication and straightforward
                  bindings of AAA information to application
                    layer using well-defined mechanism.

TLS SCA specifies attributes, operations and authentication workflow for the 
process of channel binding on top of secure channel protocols with 
cryptographic integrity, confidentiality and straightforward bindings of AAA 
information to application layer using well-defined mechanism.

> Besides authentication and accounting on application layer is allways prone to many attacks and implementation errors compared to TLS.

## TLS has various attack mitigations features:
 - cipher negotiations
 - session negotiations and session resumption
 - safe renegotiations 
 - strong authentication

## TLS specifications provides standard and well defined mechanisms for:
 - confidential channel authentication
 - binding authenticated user context to encrypted session
 - way how to propagate these AAA information to other layers.

**URL References**

| ID              | URI                                                       |
|-----------------|-----------------------------------------------------------|
| AAA-TLS-SCA     | https://github.com/n13l/openaaa/blob/master/doc/tls-sca   |
| OPENVPN-RFC5705 | https://github.com/OpenVPN/openvpn/blob/master/doc/keying-material-exporter.txt |

