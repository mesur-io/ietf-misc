%%%
title = "Selective Disclosure CWTs (SD-CWT)"
abbrev = "sd-cwt"
ipr= "trust200902"
area = "Internet"
workgroup = "None"
submissiontype = "IETF"
keyword = ["SPICE", "COSE","CWT","CBOR","SD"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-prorock-spice-cose-sd-cwt-latest"
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

This document describes a data minimization technique for use with CBOR Web Token (CWT) [@!RFC8392].
The approach is based on SD-JWT [@?I-D.ietf-oauth-selective-disclosure-jwt], with changes to align with CBOR Object Signing and Encryption (cose).
This document updates RFC8392.

{mainmatter}

# Notational Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**",
"**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this
document are to be interpreted as described in [@!RFC2119].

# Terminology

The terminology used in this document is inherited from RFC8392, RFC9052 and RFC9053.

This document defines the following new terms related to concepts originally described in SD-JWT.

SD-CWT (Selective Disclosure CBOR Web Token (CWT))
: A CWT equivalent of an SD-JWT. Unlike SD-JWT, SD-CWT is not a new token type, it is a profile of CWT. This is the CWT equivalent of application/sd-jwt.

sd_kbt
: A CWT used to demonstrate possession of a confirmation method, associated to an SD-CWT. This is the CWT counterpart to application/kb+jwt. The key binding token is included in the `sd_kwt` claim in the unprotected header of SD-CWT presentations.

Disclosures
: The salted claims disclosed via an SD-CWT. They are included in the `sd_claims` array in the unprotected header.

redacted_keys
: The hashes of claims redacted from a map data structure.

redacted_element
: The hashes of elements redacted from an array data structure. 

presented_sd_claims
: The CBOR map containing zero or more disclosable claims.

validated_presented_sd_claims
: The CBOR map containing all mandatory to disclose claims signed by the issuer, all selectively disclosed claims presented by the holder, and ommiting all instances of redacted_keys and redacted_element claims that are present in the original sd_cwt.

## Introduction

This document updates RFC8392, enabling the holder of a CWT to disclose or redact special claims marked disclosable by the issuer of a CWT.
The approach is modeled after SD-JWT, with changes to align with conventions from CBOR Object Signing and Encryption (COSE). 

The ability to minimize disclosure of sensitive identity attributes, while demonstrating possession of key material and enabling a verifier to confirm the attributes have been unaltered by the issuer, is an important building block for many digital credential use cases.

The approach described in this specification is not new. SD-JWT was modeled after mDoc, both of which enable similar capabilities.
This specification brings selective disclosure capabilities to CWT, enabling application profiles to impose additional security criteria beyond the minimum security requirements this specification requires.

Specific use cases are out of scope for this document.
However, feedback has been gathered from a wide range of stakeholders, some of which is reflected in the examples provided in the appendix.

## Issuance & Presentation

Figure 1: High level SD-CWT Issuance and Presentation Flow

``` aasvg
Issuer                                 Holder                                    Verifier 
  │                                      │                                          │     
  │                                      ├───┐                                      │     
  │                                      │   │ Key Gen                              │     
  │              Request SD-CWT          │◄──┘                                      │     
  │◄─────────────────────────────────────┤                                          │     
  │                                      │                                          │     
  ├─────────────────────────────────────►│             Request Nonce                │     
  │              Receive SD-CWT          ├─────────────────────────────────────────►│     
  │                                      │                                          │     
  │                                      │◄─────────────────────────────────────────┤     
  │                                      │             Receive Nonce                │     
  │                                      ├───┐                                      │     
  │                                      │   │ Redact Claims                        │     
  │                                      │◄──┘                                      │     
  │                                      │                                          │     
  │                                      ├───┐                                      │     
  │                                      │   │ Demonstrate                          │     
  │                                      │◄──┘ Posession                            │     
  │                                      │                                          │     
  │                                      │             Present SD-CWT               │     
  │                                      ├─────────────────────────────────────────►│     
  │                                      │                                          │     
```

This diagram captures the essential details necessary to issue and present an SD-CWT.
The parameters necessary to support these processes can be obtained using transports or protocols which are out of scope for this specification.
However the following guidance is generally recommneded regardless of protocol or transport.

1. The issuer SHOULD confirm the holder controls all confirmation material before issuing credentials using the `cnf` claim.
2. The verifier SHOULD use a nonce (cnonce), to protect against replay attacks. 

## Creating an SD-CWT

SD-CWT is modeled after SD-JWT, with adjustments to align with conventions in CBOR and COSE.

An SD-CWT is a CWT containing the hash digests of the claim values combined with unique random salts and additional metadata for disclosed values.

A Holder key binding CWT (see next section) MUST be present in a `sd_kbt` claim in the unprotected header when presenting an SD-CWT to a Verifier.

There does not exist a concept of "SD-CWT without key binding".

The following informative CDDL is provided.

Please note this example contains claims for demonstration of the disclosure syntax, such as `swversion`.

`sd_kbt` is marked optional because it is not present after issuance, however is MUST be present in all subsequent presentations of the sd-cwt.

``` cddl
sd-cwt = [
  protected,
  unprotected: {
    ?(sd_claims: TBD): bstr .cbor [ + claim-pair],
    ?(sd_kbt: TBD): bstr .cbor sd-cwt-kbt,
  },
  payload :  bstr .cbor {
    &(iss: 1) => tstr, ; "https://issuer.example"
    &(sub: 2) => tstr, ; "https://device.example"
    &(aud: 3) => tstr, ; "https://verifier.example"
    &(exp: 4) => int,  ; 1883000000
    &(nbf: 5) => int,  ; 1683000000
    &(iat: 6) => int,  ; 1683000000
    &(cnf: 8) => sd-cwt-cnf,  ; 1683000000

    ; sd-cwt new claims
    &(sd_alg: TBD) => int,            ; -16 for sha-256
    &(redacted_keys: TBD) => [ bstr ] ; redacted map key
    &(swversion: 271) => [              ; example array
      ...,
      {
        &(redacted_element: TBD) => bstr ; redacted array element
      }
      ...
    ]      
  }
  signature : bstr,
]
```

Disclosures are structured as a "sd-cwt-claim-pair" with a 32 bit salt, and the byte string of the disclosed value.

``` cddl
sd-cwt-claim-pair = [
  uint .size 4,  ; 32-bit salt
  bstr           ; disclosed value
]
```

Confirmation is established according to RFC 8747, using the `cnf` claim.

The following informative CDDL is provided, however new confirmation methods might be registered and used after this document is published.

``` cddl
sd-cwt-cnf = COSE_Key / Encrypted_COSE_Key / kid
```

The proof of possession associated with the confirmation claim in an SD-CWT is called the SD-CWT-KBT.
As noted above, this token MUST be present in presentations of the SD-CWT and MUST NOT be present in the issued form of the SD-CWT which is first delivered from an issuer to a client.

``` cddl
sd-cwt-kbt = [
  protected: bstr .cbor { 
    &(alg: 1) => int  ; CWT algorithm
    &(typ: 16) => int ; Explicit type according to draft-ietf-cose-typ-header-parameter
  },
  unprotected: {},
  payload : bstr .cbor {
    &(cnonce: 39) => bstr,   ; e0a156bb3f
    &(aud: 3) => tstr, ; "https://verifier.example"
    &(iat: 6) => int,  ; 1683000000
    &(sd_hash: TBD) => bstr, ; f0e4c2f76c589...61b1816e13b

    ?(exp: 4) => int,  ; 1883000000
    ?(nbf: 5) => int,  ; 1683000000

    ; additional CWT claims are allowed.
  }
  signature : bstr,
]
```

## Validating an SD-CWT

The exact order of the following steps MAY be changed, as long as all checks are performed before deciding if an SD-CWT is valid.

First the verifier must validate the SD-CWT as described in {{Section 7.2 of RFC 8392}}.

After validation, the SD-CWT-KBT MUST be extracted from the unprotected header, and validated as described in {{Section 7.2 of RFC 8392}}.

The verifier MUST confirm the `sd_hash` claim of the validated SD-CWT-KBT matches the hash of the `sd_claims` member of the unprotected header, using the hash algorithm obtained from the validated `sd_alg` claim of the SD-CWT.

Next, the verifier MUST extract and decode the disclosed claims from the `sd_claims` in the unprotected header.

The decoded `sd_claims` are converted to an intermediate data structure called `presented_sd_claims` which is used to transform the presented SD-CWT claimset, into a validated SD-CWT claimset containing no redaction claims.

One possible concrete representation of the intermediate data structure `presented_sd_claims` could be:

``` cddl-ish
{
  &(digest_of_salt_and_disclosure: bstr) => sd-cwt-claim-pair-disclosed-value
}
```

The verifier MUST compute the hash of the sd-cwt-claim-pair, in order to match the disclosed value to redacted claims in the SD-CWT.

To verify an SD-CWT, the recipient extracts the protected CWT claims from the payload. 
These CWT claims contain hash digests of the original claim values combined with unique random salts.

By performing these steps, the recipient can cryptographically verify the integrity of the protected claims and verify they have not been tampered with or substituted after issuance by the trusted issuer. 
The disclosures provide the plaintext claim values for utilization by the recipient.

The algorithm for transorming the CWT Claimset mirrors the algorithm defined in SD-JWT.
The primary differences are that CBOR maps have replaced JSON Objects, and that CBOR labels (integers) have replaced the strings used by SD-JWT which are `_sd` and `...`.
This specification uses the term `validated_presented_sd_claims` to refer to the final CBOR map which is produced by subsituting disclosed values which are presented, and removing labels marked for redaction.

As described in SD-JWT, if there remain unused SD-CWT disclosures at the end of this procedure the SD-CWT MUST be considered invalid, as if the siganture had failed to verify.

## Examples

TBD - Provide more examples

### Minimal spanning example

The following example contains claims needed to demonstrate redaction of key-value pairs and array elements.

``` cbor-diag
/ cose-sign1 / 18([
  / protected / << {
    / alg / 1 : -35 / ES384 /
    / typ / 16 : "application/sd+cwt"
  } >>,
  / unprotected / {
    / sd_claims / TBD : h'82501bb4...6c655f32'
    / sd_kbt    / TBD : << [
      / protected / << {
          / alg / 1 : -35 / ES384 /
          / typ / 16 : "application/kb+cwt"
      } >>,
      / unprotected / {},
      / payload / <<
        / cnonce / 39   : h'e0a156bb3f',
        / aud     / 3   : "https://verifier.example",
        / iat     / 6   : 1783000000,
        / sd_hash / TBD : h'c341bb4...a5f3f',
      >>,
      / signature / h'1237af2e...6789456'
    ] >>
  },
  / payload / <<
    / iss / 1   : "https://issuer.example",
    / sub / 2   : "https://device.example",
    / exp / 2   : 1883000000,
    / iat / 2   : 1683000000,
    / cnf / 8   : {
      / cose key / 1 : {
        / alg: ES256 /  3: 35,
        / kty: EC2   /  1: 2,
        / crv: P-256 / -1: 1,
        / x / -2: h'768ed8...8626e',
        / y / -3: h'6a48cc...fd5d5'
      }
    },

    / sd_alg / TBD        : -16, / SHA-256 /
    / redacted_keys / TBD : [ 
      / redacted age_over_18 / h'abbd...efef',
      / redacted age_over_21 / h'132d...75e7',
    ]
    / swversion / 271 : [
      "3.5.5",
      { / redacted version / TBD: h'45dd...87af }
    ]
  >>,
  / signature / h'3337af2e...66959614'
])
```

# Security Considerations

Security considerations from COSE [@!RFC9052] and CWT [@!RFC8392] apply to this specificaton.

## Random Numbers

The salts used to protect disclosed claims MUST be generated independently from a source of entropy that is acceptable to the issuer.
Poor choice of salts can lead to brute force attacks that can reveal redacted claims.

# IANA Considerations

## COSE Header Parameters

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cose/cose.xhtml#header-parameters).

### sd_claims

The following completed registration template per RFC8152 is provided:

Name: sd_claims
Label: TBD (requested assignment TBD)
Value Type: bstr
Value Registry: (empty)
Description: Claims disclosed selectively
Reference: RFC XXXX

### sd_kbt

The following completed registration template per RFC8152 is provided:

Name: sd_kbt
Label: TBD (requested assignment TBD)
Value Type: bstr
Value Registry: (empty)
Description: Key binding token for disclosed claims
Reference: RFC XXXX

## CBOR Web Token (CWT) Claims

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cwt/cwt.xhtml).

### sd_alg

The following completed registration template per RFC8392 is provided:

Claim Name: sd_alg
Claim Description: Hash algorithm used for selective disclosure
JWT Claim Name: sd_alg
Claim Key: TBD (request assignment TBD)
Claim Value Type(s): integer
Change Controller: IETF
Specification Document(s): RFC XXXX

### sd_hash

The following completed registration template per RFC8392 is provided:

Claim Name: sd_hash
Claim Description: Hash of encoded disclosed claims
JWT Claim Name: sd_hash
Claim Key: TBD (request assignment TBD)
Claim Value Type(s): bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### redacted_keys

The following completed registration template per RFC8392 is provided:

Claim Name: redacted_keys
Claim Description: Redacted claims in a map.
JWT Claim Name: redacted_keys
Claim Key: TBD (request assignment TBD)
Claim Value Type(s): array of bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### redacted_element

The following completed registration template per RFC8392 is provided:

Claim Name: redacted_element
Claim Description: Redacted element of an array
JWT Claim Name: redacted_element
Claim Key: TBD (request assignment TBD)
Claim Value Type(s): array of bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

## Media Types

This section requests the registration of new media types in https://www.iana.org/assignments/media-types/media-types.xhtml.

### application/sd+cwt

IANA is requested to add the following entry to the media types registry in accordance with RFC6838, RFC4289, and RFC6657.

The following completed registration template is provided:

* Type name: application
* Subtype name: sd+cwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary
* Security considerations: See the Security Considerations section
  of RFC XXXX, and [@!RFC8392]
* Interoperability considerations: n/a
* Published specification: RFC XXXX
* Applications that use this media type: TBD
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
* Change controller: IETF
* Provisional registration?  No

### application/kb+cwt

IANA is requested to add the following entry to the media types registry in accordance with RFC6838, RFC4289, and RFC6657.

The following completed registration template is provided:

* Type name: application
* Subtype name: kb+cwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary
* Security considerations: See the Security Considerations section
  of RFC XXXX, and [@!RFC8392]
* Interoperability considerations: n/a
* Published specification: RFC XXXX
* Applications that use this media type: TBD
* Fragment identifier considerations: n/a
* Additional information:
      Magic number(s): n/a
      File extension(s): n/a
      Macintosh file type code(s): n/a
* Person & email address to contact for further information:
  Orie Steele, orie@transmute.industries
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Orie Steele, orie@transmute.industries
* Change controller: IETF
* Provisional registration?  No

# Implementation Status

Note to RFC Editor: Please remove this section as well as references to {{BCP205}} before AUTH48.

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{BCP205}}.
The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.
Please note that the listing of any individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist.

According to {{BCP205}}, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.
It is up to the individual working groups to use this information as they see fit".

## Transmute Prototype

Organization: Transmute Industries Inc

Name: https://github.com/transmute-industries/sd-cwt

Description: An open source implementation of this draft.

Maturity: Prototype

Coverage: The current version ('main') implements functionality similar to that described in this document, and will be revised, with breaking changes to support the generation of example data to support this specification.

License: Apache-2.0

Implementation Experience: No interop testing has been done yet. The code works as proof of concept, but is not yet production ready.

Contact: Orie Steele (orie@transmute.industries)

# Acknowledgements 

The authors would like to thank those that have worked on similar items
for providing selective disclosure mechanisms in JSON, especially:
Brent Zundel, Roy Williams, Tobias Looker, Kristina Yasuda, Daniel Fett, 
Oliver Terbu, and Michael Jones.

{backmatter} 

