%%%
title = "Selective Disclosure CWTs (SD-CWT)"
abbrev = "sd-cwt"
ipr= "trust200902"
area = "Internet"
workgroup = "None"
submissiontype = "IETF"
keyword = ["COSE","CWT","CBOR","SD"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-prorock-cose-sd-cwt-latest"
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

This document describes how to perform selective disclosure of claims
withing a CBOR Web Token (CWT) [@!RFC8392] as well as how to create and
verify those tokens.

This document does not define any new cryptography.


{mainmatter}

# Notational Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**",
"**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this
document are to be interpreted as described in [@!RFC2119].

# Terminology

The following terminology is used throughout this document:

signature
: The digital signature output.

Claim Name
: The human-readable name used to identify a claim.

Claim Key
: The CBOR map key used to identify a claim.

Claim Value
: The CBOR map value representing the value of the claim.

CWT Claims Set
: The CBOR map that contains the claims conveyed by the CWT.


# Selective disclosure of claims within a CWT

## Overview

CBOR claims are cpommonly signed using [COSE
Sign1](https://www.rfc-editor.org/rfc/rfc9052#section-4.2) where only
one signature is placed on a particular message.  There are many cases
where a signer may wish to ensure that the authenticity of a message has
not been compromised via a digital signature, but where they only wish
to reveal some values of the original signed message.  This document
outlines a precise method for formulating and transmitting these
messages, encompassing elements such as claims, claim keys, and
necessary data structures. This kind of signed information exchange
proves particularly beneficial in scenarios where a CBOR Web Token (CWT)
might transit via an intermediary before undergoing third-party
verification. Frequently, such a third party might necessitate, or be
permitted to access only a subset of the information encapsulated in the
CWT. This proposed model facilitates selective data disclosure, while
still preserving the ability to validate the original signature.

This representation relies on claims registered in the [IANA CBOR Web
Token (CWT) Claims Registry](https://www.iana.org/assignments/cwt/cwt.xhtml) 
whenever possible.

## Flow Diagram

Figure 1: SD-CWT Issuance and Presentation Flow

```
           +------------+
           |            |
           |   Issuer   |
           |            |
           +------------+
                 |
               Issues
               SD-CWT
                 |
                 v
           +------------+
           |            |
           |   Holder   |
           |            |
           +------------+
                 |
              Presents
               SD-CWT
                 |
                 v
           +-------------+
           |             |+
           |  Verifiers  ||+
           |             |||
           +-------------+||
            +-------------+|
             +-------------+
```

## Creating an SD-CWT

An SD-CWT is a CWT of the hash digests of the claim values with unique
random salts and other metadata. It MUST be digitally signed using the
issuer's private key.

```
SD-CWT-CLAIMS = (METADATA, CWT-CLAIMS)
SD-CWT = SD-CWT-CLAIMS | SIG(SD-CWT-CLAIMS, ISSUER-PRIV-KEY)
```

CWT-CLAIMS is a simple object with claim names mapped to hash digests
over the claim values with unique random salts:

```
CWT-CLAIMS = (
    CLAIM-NAME: HASH(SALT | CLAIM-VALUE)
)*
```

In a case where an SD-CWT is sent with all information disclose, the
SD-CWT is sent together with the mapping of the plain-text claim values,
the salt values, and potentially some other information. In this case,
the the payload contains the CWT-CLAIMS, and the field "disclosures"
contains the mapping, the salt values, and other metadata.

In a case where an SD-CWT is sent with only some information discosed,
only the desired claims, mappings, and salts are added to the
disclosure.

The CDDL fragment that represents the above text for COSE_Sign1 follows.

```
SD-CWT = [
    Headers,
    payload : bstr / nil,
    signature : bstr,
    disclosures: bstr / nil
]
```

## Verifying an SD-CWT

TBD - Describe verifiacation process

## Holder Binding and other common scenarios

### Holder Binding

TBD - Discuss optioinality, mechanism, and value

### Counter Signatures

TBD- Discuss use with countersignatures in the unprotected header

## Data Structures

TBD - Describe common data structures in CDDL

## Examples

TBD - Provide examples

# Security Considerations

All security considerations from COSE [@!RFC8152] and CWT [@!RFC8392]
SHOULD be followed.

To maintain the integrity of the issued claims, the Selective
Disclosure-CBOR Web Token (SD-CWT) MUST be signed by the issuer. Absence
of this signature leaves the SD-CWT vulnerable to attackers, who can
alter or append claims (for instance, modifying the "email" attribute to
hijack the victim's account or inserting a fabricated academic
qualification).

The verifier is required to verify the signature on the SD-CWT to
guarantee its authenticity and that no tampering has occurred post
issuance. If the signature on the SD-CWT fails the verification process,
the SD-CWT MUST be unequivocally rejected.

# IANA Considerations

## Media Type Registration

This section will register the "application/sd-cwt" media type [@!RFC2046]
in the "Media Types" registry [IANA.MediaTypes] in the manner described
in RFC 6838 [@!RFC6838], which can be used to indicate that the content is
a CWT.

* Type name: application
* Subtype name: sd-cwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary
* Security considerations: See the Security Considerations section
  of [@!RFC8392]
* Interoperability considerations: n/a
* Published specification: This Specification
* Applications that use this media type: mesur.io, transmute
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

# Acknowledgements 

The authors would like to thank those that have worked on similar items
for providing selective disclosure mechanisms in JSON, especially:
Tobias Looker, Kristina Yasuda, Daniel Fett, Oliver Terbu, and Michael
Jones.

{backmatter} 

