%%%
title = "Native JWT Representation of Verifiable Credentials"
abbrev = "native-jwt-vcs"
ipr= "trust200902"
area = "Internet"
workgroup = "None"
submissiontype = "IETF"
keyword = ["JOSE","COSE","JWT","CWT"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-prorock-jose-native-jwt-vcs-latest"
stream = "IETF"
status = "standard"

[pi]
toc = "yes"

[[author]]
initials = "M."
surname = "Prorock"
fullname = "Michael Prorock"
organization = "mesur.io"
  [author.address]
  email = "mprorock@mesur.io"

[[author]]
initials = "O."
surname = "Steele"
fullname = "Orie Steele"
organization = "Transmute"
  [author.address]
  email = "orie@transmute.industries"


%%%

.# Abstract

This document describes how to construct and utilize
a JWT as a Verifiable Credential utilizing only JSON
and registered claims.

This document does not define any new cryptography,
only seralizations of systems.


{mainmatter}

# Notational Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**",
"**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this
document are to be interpreted as described in [@!RFC2119].

# Terminology

The following terminology is used throughout this document:

signature
: The digital signature output.


# Native JWT Representation of Verifiable Credentials

## Overview

This section provides guidance on how to use JSON [@!RFC8259] claimsets
with JWT [@!RFC7519] registered claims to construct a JWT that can be mapped to a
verifiable credential. This section also describes how to use content
types and token types to distinguish different representations of
verifiable credentials.

This representation relies on claims registered in the [IANA
JSON Web Token Claims Registry](https://www.iana.org/assignments/jwt/jwt.xhtml#claims)
whenever possible.

Implementers using this representation SHOULD NOT use `vc+ld+json` as
an input.

### Credential Header

`typ` MUST use the media type `vc+jwt`.

Example of credential metadata (decoded JWT header):

```json
{
  "kid": "https://example.edu/issuers/14#key-0",
  "alg": "ES256",
  "typ": "vc+jwt"
}
```

### Credential

Example of a credential (decoded JWT payload):

```json
{ 
  "iss": "https://example.edu/issuers/14",
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "urn:example:claim": true
}
```

NOTE: The `vc` and `vp` claims MUST NOT be present when the content
type header parameter is set to `credential-claims-set+json`.

### Verifiable Credential

Example of an JWT encoded verifiable credential (using external proof):

```json
=============== NOTE: '\' line wrapping per RFC 8792 ================
eyJraWQiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvMTQja2V5LTAiLCJhbGci\
OiJFUzI1NiIsInR5cCI6InZjK2p3dCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR\
1L2lzc3VlcnMvMTQiLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiw\
iaWF0IjoxNTE2MjM5MDIyLCJ1cm46ZXhhbXBsZTpjbGFpbSI6dHJ1ZX0.WLD4Qxh629T\
FkJHzmbkWEefYX-QPkdCmxbBMKNHErxND2QpjVBbatxHkxS9Y_SzBmwffuM2E9i5VvVg\
pZ6v4Tg
```

# Security Considerations

All security considerations from JSON [@!RFC8259] and JWT [@!RFC7519]
SHOULD be followed.

# IANA Considerations

## Media Type Registration

This section will register the "application/vc+jwt" media type [RFC2046]
in the "Media Types" registry [IANA.MediaTypes] in the manner described
in RFC 6838 [RFC6838], which can be used to indicate that the content is
a JWT.

* Type name: application
* Subtype name: vc+jwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: 8bit; JWT values are encoded as a series
  of base64url-encoded values (some of which may be the empty
  string) separated by period ('.') characters.
* Security considerations: See the Security Considerations section
  of RFC 7519
* Interoperability considerations: n/a
* Published specification: n/a
* Applications that use this media type: OpenID Connect, Mozilla
* Persona, Salesforce, Google, Android, Windows Azure, Amazon Web
* Services, and numerous others
* Fragment identifier considerations: n/a
* Additional information:
      Magic number(s): n/a
      File extension(s): n/a
      Macintosh file type code(s): n/a
* Person & email address to contact for further information:
  Michael Prorock, mprorock@mesur.io
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Michael Prorock, mprorock@mesur.io
* Change controller: IESG
* Provisional registration?  Yes


{backmatter} 

