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
The approach is based on SD-JWT [@?I-D.ietf-oauth-selective-disclosure-jwt], with changes to align with CBOR Object Signing and Encryption (COSE).
This document updates RFC8392.

{mainmatter}

# Notational Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**",
"**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this
document are to be interpreted as described in [@!RFC2119].

# Terminology

The terminology used in this document is inherited from RFC8392, RFC9052 and RFC9053.

This document defines the following new terms related to concepts originally described in SD-JWT.

Selective Disclosure CBOR Web Token (SD-CWT)
: A CWT with claims enabling selective disclosure with key binding.

Selective Disclosure Key Binding Token (SD-CWT-KBT)
: A CWT used to demonstrate possession of a confirmation method, associated to an SD-CWT.

Salted Disclosed Claims
: The salted claims disclosed via an SD-CWT.

Digested Salted Disclosed Claim
: A hash digest of a Salted Disclosed Claims.

Redacted keys
: The hashes of claims redacted from a map data structure.

Redacted elements
: The hashes of elements redacted from an array data structure. 

Presented Disclosed Claimset
: The CBOR map containing zero or more Redacted keys or Redacted elements.

Validated Disclosed Claimset
: The CBOR map containing all mandatory to disclose claims signed by the issuer, all selectively disclosed claims presented by the holder, and ommiting all instances of redacted_keys and redacted_element claims that are present in the original sd_cwt.

Issuer
: An entity that produces a Selective Disclosure CBOR Web Token.

Holder
: An entity that presents a Selective Disclosure CBOR Web Token which includes a Selective Disclosure Key Binding Token.

Partial Disclosure
: When a subset of the original claims protected by the Issuer, are disclosed by the Holder. 

Full Disclosure
: When the full set of claims protected by the Issuer, is disclosed by the Holder. 

Verifier
: An entity that validates a Partial or Full Disclosure by a holder.

# Introduction

This document updates RFC8392, enabling the holder of a CWT to disclose or redact special claims marked disclosable by the issuer of a CWT.
The approach is modeled after SD-JWT, with changes to align with conventions from CBOR Object Signing and Encryption (COSE). 
The ability to minimize disclosure of sensitive identity attributes, while demonstrating possession of key material and enabling a verifier to confirm the attributes have been unaltered by the issuer, is an important building block for many digital credential use cases.
This specification brings selective disclosure capabilities to CWT, enabling application profiles to impose additional security criteria beyond the minimum security requirements this specification requires.
Specific use cases are out of scope for this document.
However, feedback has been gathered from a wide range of stakeholders, some of which is reflected in the examples provided in the appendix.

## Overview

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
However the following guidance is generally recommended, regardless of protocol or transport.

1. The issuer SHOULD confirm the holder controls all confirmation material before issuing credentials using the `cnf` claim.
2. To protect against replay attacks, the verifier SHOULD provide a nonce, and reject requests that do not include an acceptable an nonce (cnonce). This guidance can be ignored in cases where replay attacks are mitigated at another layer.

# SD-CWT Issuance

An SD-CWT is a CWT containing zero or more Digested Salted Disclosed Claim, and zero or more Salted Disclosed Claims.
The salt acts as a blinding factor, preventing a Verifier of an SD-CWT from learning claims that were not intentionally disclosed by a Holder.
A confirmation claim `cnf (8)` MUST be present in the CWT Claimset.
The `sd_kbt` MUST NOT be set by the Issuer, and MUST be set by the Holder, and is therefore marked optional in the following normative defintion of SD-CWT in CDDL:

``` cddl

digested-salted-disclosed-claim = bstr; 
salted-disclosed-claim = salted-claim / salted-element
salted-claim = [
  bstr .size 16,  ; 128-bit salt
  (int / text),   ; claim name
  any             ; claim value
]
salted-element = [
  bstr .size 16, ; 128-bit salt
  any            ; claim value
]
sd-cwt-cnf = COSE_Key / Encrypted_COSE_Key / kid
sd-cwt = [
  protected,
  unprotected: {
    ?(sd_claims: TBD1): bstr .cbor [ + salted-disclosed-claim ],
    ?(sd_kbt: TBD2): bstr .cbor sd-cwt-kbt,
  },
  payload :  bstr .cbor {
    ?(iss: 1) => tstr, ; "https://issuer.example"
    ?(sub: 2) => tstr, ; "https://device.example"
    ?(aud: 3) => tstr, ; "https://verifier.example"
    ?(exp: 4) => int,  ; 1883000000
    ?(nbf: 5) => int,  ; 1683000000
    ?(iat: 6) => int,  ; 1683000000
    &(cnf: 8) => sd-cwt-cnf,  ; 1683000000

    ?(sd_alg: TBD4) => int,             ; -16 for sha-256
    ?(redacted_keys: TBD5) => [         ; redacted map keys
      digested-salted-disclosed-claim 
    ],

    ; redaction in an example map value that is an array 
    &(example-array-key: -65537) => [  
      123,
      { ; redacted array element
        &(redacted_element: TBD6) =>
        digested-salted-disclosed-claim 
      },
      789,
      { ; redacted array element
        &(redacted_element: TBD6) =>
        digested-salted-disclosed-claim 
      },
    ]
  }
  signature : bstr,
]
```

As described above, an SD-CWT is a CWT with claims that require confirmation and support selective disclosure.
Confirmation mitigates risks associated with bearer token theft.
Note that new confirmation methods might be registered and used after this document is published.
Selective disclosure enables data minimization.
The mechanism through which map keys and array elements are disclosed is different, see SD-CWT Validation for details.
CWT Claims which are not explictly marked redactable by the Issuer are mandatory to disclose by the Holder.
A detailed privacy and security analysis of all mandatory and optionally disclosed claims SHOULD be performed prior to issuance.

# SD-CWT Presentation

Presentations of an SD-CWT by a Holder to a Verifier require the Holder to issue an SD-CWT-KBT. 

The SD-CWT-KBT is essential to assuring the Verifier:

- a) the Holder of the SD-CWT controls the confirmation method chosen by the Issuer.
- b) the Holder's disclosures have not been tampered with since confirmation occured.

The SD-CWT-KBT prevents an attacker from copying and pasting disclosures, or from adding or removing disclosures without detection. 
Confirmation is established according to RFC 8747, using the `cnf` claim in the payload of the SD-CWT. 
The Digested Salted Disclosed Claim are included in the `sd_hash` claim in the payload of the SD-CWT-KBT.

The proof of possession associated with the confirmation claim in an SD-CWT is called the SD-CWT-KBT.
As noted above, SD-CWT Issuance, `sd_kbt` SHALL be present in every presentation of an SD-CWT by a Holder to a Verifier.

``` cddl
digested-sd-claims = bstr ; 
sd-cwt-kbt = [
  protected: bstr .cbor { 
    ?(alg: 1) => int  ; CWT algorithm
    ?(typ: 16) => int ; Explicit type according to draft-ietf-cose-typ-header-parameter
  },
  unprotected: {},
  payload : bstr .cbor {
    &(cnonce: 39) => bstr,   ; e0a156bb3f
    &(aud: 3) => tstr, ; "https://verifier.example"
    &(iat: 6) => int,  ; 1683000000
    &(sd_hash: TBD3) => digested-sd-claims, ; f0e4c2f76c589...61b1816e13b

    ?(exp: 4) => int,  ; 1883000000
    ?(nbf: 5) => int,  ; 1683000000

    ; additional CWT claims are allowed.
  }
  signature : bstr,
]
```

Note that `sd_hash` is the digest using `sd_alg` of the `sd_claims` which are either Partially or Fully Redacted in the Presented SD-CWT.

The `cnonce` and `audience` are essential to assure the Verifier that the Holder is currently in control of the associated confirmation method, and that the holder intended to disclose the SD-CWT to the Verifier.

Note that `cnonce` is a `bstr` and MUST be treated as opaque to the Holder.

The details associated with these protocol parameters are out of scope for this document.

# SD-CWT Validation

The exact order of the following steps MAY be changed, as long as all checks are performed before deciding if an SD-CWT is valid.

First the Verifier must validate the SD-CWT as described in {{Section 7.2 of RFC 8392}}.

After validation, the SD-CWT-KBT MUST be extracted from the unprotected header, and validated as described in {{Section 7.2 of RFC 8392}}.

The Verifier MUST confirm the `sd_hash` claim of the validated SD-CWT-KBT matches the hash of the `sd_claims` member of the unprotected header, using the hash algorithm obtained from the validated `sd_alg` claim of the SD-CWT.

Next, the Verifier MUST extract and decode the disclosed claims from the `sd_claims` in the unprotected header.

The decoded `sd_claims` are converted to an intermediate data structure called a Digest To Disclosed Claim Map which is used to transform the Presented Disclosed Claimset, into a Validated Disclosed Claimset.

The Verifier MUST compute the hash of each `salted-disclosed-claim`, in order to match each disclosed value to each entry of the Presented Disclosed Claimset.

One possible concrete representation of the intermediate data structure for the Digest To Disclosed Claim Map could be:

``` cddl-ish
{
  &(digested-salted-disclosed-claim) => salted-disclosed-claim
}
```

The Verifier constructs an empty cbor map called the Validated Disclosed Claimset, and initializes it with all mandatory to disclose claims from the verified Presented Disclosed Claimset.

Next the Verifier performs a breadth first or depth first traversal of the Presented Disclosed Claimset, Validated Disclosed Claimset, using the Digest To Disclosed Claim Map to insert claims into the Validated Disclosed Claimset when they appear in the Presented Disclosed Claimset.
By performing these steps, the recipient can cryptographically verify the integrity of the protected claims and verify they have not been tampered with.
If there remain unused Digest To Disclosed Claim Map at the end of this procedure the SD-CWT MUST be considered invalid, as if the siganture had failed to verify.
Otherwise the SD-CWT is considered valid, and the Validated Disclosed Claimset is now a CWT Claimset with no claims marked for redaction.
Further validation logic can be applied to the Validated Disclosed Claimset, as it might normally be applied to a validated CWT claimset.


## Credential Types

This specification defines the CWT claim vct (for verifiable credential type). The vct value MUST be a case-sensitive StringOrURI (see [RFC7519]) value serving as an identifier for the type of the SD-CWT claimset. The vct value MUST be a Collision-Resistant Name as defined in Section 2 of [RFC7515].

This claim is defined COSE based verifiable credentials, similar to the JOSE based verifiable credentials described in Section 3.2.2.1.1 of SD-JWT-VC.

Profiles built on this specifiation are also encouraged to use more specific media types, as described in [draft-ietf-cose-typ-header-parameter](https://datatracker.ietf.org/doc/draft-ietf-cose-typ-header-parameter/).


# Examples

TBD - Provide more examples

## Minimal spanning example

The following example contains claims needed to demonstrate redaction of key-value pairs and array elements.

``` cbor-diag
/ cose-sign1 / 18([
  / protected / << {
    / alg / 1  : -35 / ES384 /
    / typ / 16 : "application/sd+cwt"
    / kid /    : "https://issuer.example/cwt-key3"
  } >>,
  / unprotected / {
    / disclosed claims /
    / sd_claims / TBD1 : <<[  
        [
            / salt /   h'c93c7ff5...72c71e26',
            / claim /  "age_over_18",
            / value /  true
        ],
        [
            / salt /   h'399c641e...2aa18c1e',
            / claim /  "region",
            / value /  "ca" / California /
        ],
        [
            / salt /   h'82501bb4...6c655f32',
            / value /  "4.1.7"
        ]
    ]
    / sd_kbt    / TBD2 : << [
      / protected / << {
          / alg / 1 : -35 / ES384 /
          / typ / 16 : "application/kb+cwt"
      } >>,
      / unprotected / {},
      / payload / <<
        / cnonce / 39    : h'e0a156bb3f',
        / aud     / 3    : "https://verifier.example",
        / iat     / 6    : 1783000000,
        / sd_alg  / TBD4 : -16  /SHA-256/ 
        / sd_hash / TBD3 : h'c341bb...4a5f3f',  / hash of sd_claims  /
                                                / using sd_alg       /
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
    / sd_alg / TBD4        : -16, / SHA-256 /
    / redacted_keys / TBD5 : [ 
        h'abbd...efef',  / redacted age_over_18 /
        h'132d...75e7',  / redacted age_over_21 /
    ],
    / example array as map value / -65537 : [
      123,
      { TBD6 : h'45dd...87af'  / redacted_element / },
      789,
      { TBD6 : h'45dd...87af'  / redacted_element / },
    ],
    "address": {
        "country" : "us",            / United States /
        / redacted_keys / TBD5 : [
            h'adb70604...03da225b',  / redacted region /
            h'e04bdfc4...4d3d40bc'   / redacted post_code /
        ]
    }
  >>,
  / signature / h'3337af2e...66959614'
])
```

# Security Considerations

Security considerations from COSE [@!RFC9052] and CWT [@!RFC8392] apply to this specificaton.

## Random Numbers

Each salt used to protect disclosed claims MUST be generated independently from the salts of other claims. The salts MUST be generated from a source of entropy that is acceptable to the issuer.
Poor choice of salts can lead to brute force attacks that can reveal redacted claims.

# IANA Considerations

## COSE Header Parameters

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cose/cose.xhtml#header-parameters).

### sd_claims

The following completed registration template per RFC8152 is provided:

Name: sd_claims
Label: TBD (requested assignment TBD1)
Value Type: bstr
Value Registry: (empty)
Description: A list of selectively disclosed claims, which were originally redacted, then later disclosed at the discretion of the sender.
Reference: RFC XXXX

### sd_kbt

The following completed registration template per RFC8152 is provided:

Name: sd_kbt
Label: TBD (requested assignment TBD2)
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
Claim Key: TBD (request assignment TBD4)
Claim Value Type(s): integer
Change Controller: IETF
Specification Document(s): RFC XXXX

### sd_hash

The following completed registration template per RFC8392 is provided:

Claim Name: sd_hash
Claim Description: Hash of encoded disclosed claims
JWT Claim Name: sd_hash
Claim Key: TBD (request assignment TBD3)
Claim Value Type(s): bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### redacted_keys

The following completed registration template per RFC8392 is provided:

Claim Name: redacted_keys
Claim Description: Redacted claims in a map.
JWT Claim Name: redacted_keys
Claim Key: TBD (request assignment TBD5)
Claim Value Type(s): array of bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### redacted_element

The following completed registration template per RFC8392 is provided:

Claim Name: redacted_element
Claim Description: Redacted element of an array
JWT Claim Name: redacted_element
Claim Key: TBD (request assignment TBD6)
Claim Value Type(s): array of bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### vct

The following completed registration template per RFC8392 is provided:

Claim Name: vct
Claim Description: Verifiable credential type
JWT Claim Name: vct
Claim Key: TBD (request assignment TBD7)
Claim Value Type(s): bstr
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

# Comparison to SD-JWT

SD-CWT is modeled after SD-JWT, with adjustments to align with conventions in CBOR and COSE.

## Media Types

The COSE equivalent of `application/sd-jwt` is `application/sd+cwt`.

THe COSE equivalent of `application/kb+jwt` is `application/kb+cwt`.

## Redaction Claims

The COSE equivalent of `_sd` is TBD5.

The COSE equivalent of `...` is TBD6.

## Issuance

The issuance process for SD-CWT is similar to SD-JWT, with the exception that a confirmation claim is REQUIRED.

## Presentation

The presentation process for SD-CWT is similar to SD-JWT, with the exception that a Key Binding Token is REQUIRED.

## Validation

The validation process for SD-JWT is similar to SD-JWT, however, JSON Objects are replaced with CBOR Maps which can contain integer keys and CBOR Tags.