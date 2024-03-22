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

An SD-CWT is a CWT containing the hash digests of the claim values
combined with unique random salts and additional metadata for disclosed
values. The SD-CWT MUST be digitally signed using the issuer's private
key.

```
SD-CWT-CLAIMS = (METADATA, CWT-CLAIMS)
SD-CWT = SD-CWT-CLAIMS | SIG(SD-CWT-CLAIMS, ISSUER-PRIV-KEY)
```

CWT-CLAIMS is an object where claim names are mapped to hash digests of
the claim values combined with unique random salts:

```
CWT-CLAIMS = (
    CLAIM-NAME: HASH(SALT | CLAIM-VALUE)
)*
```

In a case where an SD-CWT is sent with all information disclosed, the
SD-CWT is sent together with the mapping of the plain-text claim values,
the salt values, and potentially some other information. In this case,
the the payload contains the CWT-CLAIMS, and the "disclosures" field in
the unprotected header contains the mapping, the salt values, and any
additional metadata that might be present in the unprotected header.

Disclosure in the unprotected header is important so that the content
type of the payload may be set appropriately, and is distinct from
any disclosed information. 

In a case where an SD-CWT is sent with only selected information
disclosed, only the disclosed claims, mappings, and salts are added to
the disclosure.

Disclosures are structured as a "claim-pair" with a 32 bit salt, and the
byte string of the disclosed value.


```
claim-pair = {
  1 => uint .size 4,  ; 32-bit salt
  2 => bstr           ; disclosed value
}
```

The CDDL fragment that represents the above text for COSE_Sign1 is
provided below:

```
SD-CWT = [
    protected,
    unprotected: {
      ? disclosures: [* claim-pair] / nil
    },
    payload : bstr / nil,
    signature : bstr,
]
```

The issuer SHOULD take appropriate percautions to verify that the salts
are unique random values to prevent vulnerability to rainbow table
attacks against the hashes.

## Verifying an SD-CWT

To verify an SD-CWT, the recipient extracts the protected CWT
claims from the payload. These CWT claims contain hash digests of the
original claim values combined with unique random salts.

The recipient MUST validate that the protected header values such as
issuer, audience, and expiration match the expected values for this
SD-CWT per the guidelines set forward in [@!RFC8392].  If any items do
not match the expected or allowed values per [@!RFC8392] the SD-CWT MUST
be rejected.

The payload and other protected claims MUST then be validated according
to the section "Validating a CWT" in [@!RFC8392].  If the CWT is not a
COSE_Sign or COSE_Sign1 the CWT MUST be rejected. If any validations
according [@!RFC9052] instructions for validating a COSE_Sign/COSE_Sign1
object fail, the CWT MUST be rejected.

The recipient that checks for any disclosures in the unprotected header.
If they are present, the the claim values and salts MUST be extracted
from the unprotected header.

For each disclosed claim, the hash digest MUST be recomputed from the
value and salt in the unprotected header.  If the hash digest does not
equal the corresponding digest in the payload the SD-CWT MUST be
rejected.

By performing these steps, the recipient can cryptographically verify
the integrity of the protected claims and verify they have not been
tampered with or substituted after issuance by the trusted issuer. The
disclosures provide the plaintext claim values for utilization by the
recipient.

## Holder Binding and other common scenarios

### Holder Binding

Holder binding links an SD-CWT to its intended recipient. It prevents
misuse if the token is intercepted or stolen. Binding mechanisms include
cryptographic key confirmation, biometric data inclusion, or embedding
holder-specific claims. The description of exact mechanisms for holder
binding are outside the scope of this document at the present time.

While optional, holder binding enhances SD-CWT security. It enables
accountability by auditing actions to specific entities. For sensitive
data, it augments trust by proving the claimant owns the token.

Issuers should assess their use case when considering holder binding.
Where accountability and non-repudiation are critical, binding provides
assurance the token reaches the intended holder. With thoughtful
implementation, binding can customize SD-CWT without compromising user
privacy. Proportional use of holder binding balances security, privacy
and flexibility for SD-CWT applications.

### Counter Signatures

Counter signatures allow an SD-CWT to be endorsed by additional entities
beyond the original issuer. The counter signature is applied in the
unprotected header, attesting to the validity of the primary SD-CWT
signature over the protected claims.

Counter signatures provide multiple benefits for SD-CWT:

- Verification by multiple entities, preventing repudiation by any one
  party.
- Added integrity protection in case the original signing key is
  compromised.
- Allows separate signers for protected claims versus unprotected
  disclosures.

To utilize a counter signature, the primary SD-CWT is constructed and
signed as normal. Then an additional signer computes the counter
signature over the entire SD-CWT, including the original signature. This
counter signature is placed in the unprotected header when transmitting
the SD-CWT.

Recipients validate the counter signature after verifying the primary
signature, ensuring endorsements by all involved entities. Care should
be taken to ensure robust trust in both signature authorities when
relying on counter signatures.

The CDDL fragment that represents an SD-CWT with an abbreviated counter 
signature is below:

```
SD-CWT = [
    protected,
    unprotected: {
      ? disclosures: [* claim-pair] / nil
      COSE_Countersignature0: bstr
    },
    payload : bstr / nil,
    signature : bstr,
]
```

## Data Structures

TBD - Describe common data structures in CDDL

## Examples

TBD - Provide examples

# Security Considerations

All security considerations from COSE [@!RFC9052] and CWT [@!RFC8392]
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
Brent Zundel, Roy Williams, Tobias Looker, Kristina Yasuda, Daniel Fett, 
Oliver Terbu, and Michael Jones.

{backmatter} 

