---
title: OpenID Continuous Access Evaluation Profile 1.0 - draft 03
abbrev: CAEP-Spec
docname: openid-caep-specification-1_0
date: 2023-02-09

ipr: none
cat: std
wg: Shared Signals

coding: us-ascii
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  private: yes

author:
      -
        ins: T. Cappalli
        name: Tim Cappalli
        org: Microsoft
        email: tim.cappalli@microsoft.com
      -
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
        org: SGNL
        email: atul@sgnl.ai

normative:
  ISO-IEC-29115:
    target: http://www.iso.org/iso/iso_catalogue/catalogue_tc/catalogue_detail.htm?csnumber=45138
    title: "ISO/IEC 29115:2013 -- Information technology - Security techniques - Entity authentication assurance framework"
    author:
      -
        name: "International Organization for Standardization"
    date: March 2013
  NIST-AUTH:
    target: https://pages.nist.gov/800-63-3/sp800-63-3.html
    title: "Digital Identity Guidelines, Authentication and Lifecycle Management"
    author: 
      -
        ins: P. Grassi
        name: Paul Grassi
      -
        ins: M. Garcia
        name: Michael Garcia
      -
        ins: J. Fenton
        name: James Fenton
    date: 2017-06
  NIST-FED:
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63c.pdf
    title: "Digital Identity Guidelines, Federation and Assertions"
    author: 
      -
        ins: P. A. Grassi
        name: Paul A. Grassi
      -
        ins: J. P. Richer
        name: Justin P. Richer
      -
        ins: S. K. Squire
        name: Sarah K. Squire
      -
        ins: J. L. Fenton
        name: James L. Fenton
      -
        ins: E. M. Nadeau
        name: Ellen M. Nadeau
  NIST-IDPROOF: 
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63a.pdf
    title: "Digital Identity Guidelines, Enrollment and Identity Proofing"
    author:
      -
        ins: P. A. Grassi
        name: Paul A. Grassi
      -
        ins: J. L. Fenton
        name: James L. Fenton
    date: 2017-06
  RFC2119:
  RFC8174:
  RFC5280:
  RFC5646:
  RFC6711:
  RFC8176:
  SSF:
    target: http://openid.net/specs/openid-sse-framework-1_0.html
    title: OpenID Shared Signals and Events Framework Specification 1.0
    author:
      -
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
        org: Google
      -
        ins: T. Cappalli
        name: Tim Cappalli
        org: Microsoft
      -
        ins: M. Scurtescu
        name: Marius Scurtescu
        org: Coinbase
      -
        ins: A. Backman
        name: Annabelle Backman
        org: Amazon
      -
        ins: John Bradley
        name: John Bradley
        org: Yubico
    date: 2021-05
  WebAuthn: 
    target: https://www.w3.org/TR/webauthn/
    title: "Web Authentication: An API for accessing Public Key Credentials Level 2"
    author: 
      -
        ins: D. Balfanz
        name: Dirk Balfanz
        org: Google
    date: 2021-04-8

--- abstract

This document defines the Continuous Access Evaluation Profile (CAEP) of the
Shared Signals Framework {{SSF}}. It specifies a set of event
types conforming to the Shared Signals Framework. These event types are intended to be used
between cooperating Transmitters and Receivers such that Transmitters may send
continuous updates using which Receivers can attenuate access to shared human or
robotic users, devices, sessions and applications.

--- middle

# Introduction {#introduction}
CAEP is the application of the Shared Signals Profile of IETF
Security Events 1.0 {{SSF}} (SSF Profile) to ensure access security in a
network of cooperating providers. CAEP specifies a set of event-types that
conform to the SSF Profile. This document specifies the event-types required to
achieve this goal.

## Notational Considerations
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", 
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this 
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} 
when, and only when, they appear in all capitals, as shown here.

# Optional Event Claims {#optional-event-claims}
The following claims are optional unless otherwise specified in the event
definition.

event_timestamp
: OPTIONAL, JSON number: the time at which the event described by this SET
  occurred. Its value is a JSON number representing the number of seconds 
  from 1970-01-01T0:0:0Z as measured in UTC until the date/time.

initiating_entity
: OPTIONAL, JSON string: describes the entity that invoked the event.
: This MUST be one of the following strings:

  - `admin`:    an administrative action triggered the event

  - `user`:     an end-user action triggered the event

  - `policy`:   a policy evaluation triggered the event

  - `system`:   a system or platform assertion triggered the event

reason_admin
: OPTIONAL, JSON object: a localizable administrative message intended for
logging and auditing. The object MUST contain one or more key/value pairs,
with a BCP47 {{RFC5646}} language tag as the key and the locale-specific
administrative message as the value.

~~~ json
{
    "reason_admin": {
        "en": "Landspeed Policy Violation: C076E82F",
        "de": "Landspeed-Richtlinienverstoß: C076E82F",
        "es-410": "Violación de la política de landspeed: C076E82F"
    }
}
~~~
{: #optional-claims-reason-admin-example title="Example: Administrative reason information with multiple languages"}

reason_user
: OPTIONAL, JSON object: a localizable user-friendly message for display
to an end-user. The object MUST contain one or more key/value pairs, with a
BCP47 {{RFC5646}} language tag as the key and the locale-specific end-user
message as the value.

~~~ json
{
    "reason_user": {
        "en": "Access attempt from multiple regions.",
        "de": "Zugriffsversuch aus mehreren Regionen.",
        "es-410": "Intento de acceso desde varias regiones."
    }
}
~~~
{: #optional-claims-reason-user-example title="Example: End user reason information with multiple languages"}


# Event Types {#event-types}
The base URI for CAEP event types is:

`https://schemas.openid.net/secevent/caep/event-type/`

## Session Revoked {#session-revoked}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/session-revoked`

Session Revoked signals that the session identified by the subject has been 
revoked. The explicit session identifier may be directly referenced in the 
subject or other properties of the session may be included to allow the
receiver to identify applicable sessions.

When a Complex Claim is used as the subject, the revocation event applies 
to any session derived from matching those combined claims.

The actual reason why the session was revoked might be specified with the 
nested `reason_admin` and/or `reason_user` claims described in {{optional-event-claims}}.

### Event-Specific Claims {#session-revoked-claims}

There are no event-specific claims for this event type.

When `event_timestamp` is included, its value MUST represent the time at which
the session revocation occurred.

### Examples  {#session-revoked-examples}

NOTE: The event type URI is wrapped, the backslash is the continuation character.

~~~ json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1615305159,
    "aud": "https://sp.example.com/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
            "subject": {
                "format": "opaque",
                "id": "dMTlD|1600802906337.16|16008.16"
            },
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #session-revoked-example-session-id-req title="Example: Session Revoked - Required claims + Simple Subject"}

~~~ json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1615305159,
    "aud": "https://sp.example.com/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
            "subject": {
                "session": {
                  "format": "opaque",
                  "id": "dMTlD|1600802906337.16|16008.16"
                },
                "user": {
                  "format": "iss_sub",
                  "iss": "https://idp.example.com/123456789/",
                  "sub": "99beb27c-c1c2-4955-882a-e0dc4996fcbc"
                },
                "tenant": {
                  "format": "opaque",
                  "id": "123456789"
                }
            },
            "initiating_entity": "policy",
            "reason_admin": {
                "en": "Landspeed Policy Violation: C076E82F"
            },
            "reason_user": {
                "en": "Access attempt from multiple regions.",
                "es-410": "Intento de acceso desde varias regiones."
            },
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #session-revoked-example-user-sub title="Example: Session Revoked - subject as `sub` claim (includes optional claims)"}

~~~ json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1615305159,
    "aud": "https://sp.example.com/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
            "subject": {
                "user": {
                    "format": "iss_sub",
                    "iss": "https://idp.example.com/123456789/",
                    "sub": "jane.smith@example.com"
                },
                "device": {
                    "format": "iss_sub",
                    "iss": "https://idp.example.com/123456789/",
                    "sub": "e9297990-14d2-42ec-a4a9-4036db86509a"
                },
                "tenant": {
                  "format": "opaque",
                  "id": "123456789"
                }
            },
            "initiating_entity": "policy",
            "reason_admin": {
                "en": "Policy Violation: C076E822"
            },
            "reason_user": {
                "en": "This device is no longer compliant.",
                "it": "Questo dispositivo non è più conforme."
            },
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #session-revoked-example-user-device title="Example: Session Revoked - Complex Subject describing user + device + tenant (includes optional claims)"}

## Token Claims Change {#token-claims-change}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/token-claims-change`

Token Claims Change signals that a claim in a token, identified by the 
subject claim, has changed. 

The actual reason why the claims change occurred might be specified with the 
nested `reason_admin` and/or `reason_user` claims made in {{optional-event-claims}}.

### Event-Specific Claims {#token-claims-change-claims}

claims
: REQUIRED, JSON object: one or more claims with their new value(s)

When `event_timestamp` is included, its value MUST represent the time at which
the claim value(s) changed.

### Examples  {#token-claims-change-examples}

NOTE: The event type URI is wrapped, the backslash is the continuation character.

~~~ json
{
    "iss": "https://idp.example.com/987654321/",
    "jti": "9afce1e4e642b165fcaacdd0e7aa4903",
    "iat": 1615305159,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
            "subject": {
                "format": "jwt_id",
                "iss": "https://idp.example.com/987654321/",
                "jti": "f61t6e20zdo3px56gepu8rzlsp4c1dpc0fx7"
            },
            "event_timestamp": 1615304991643,
            "claims": {
                "role": "ro-admin"
            }
        }
    }
}
~~~
{: #token-claims-change-example-oidc title="Example: OIDC ID Token Claims Change - Required claims only"}

~~~ json
{
    "iss": "https://idp.example.com/987654321/",
    "jti": "9afce1e4e642b165fcaacdd0e7aa4903",
    "iat": 1615305159,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
            "subject": {
                "format": "jwt_id",
                "iss": "https://idp.example.com/987654321/",
                "jti": "f61t6e20zdo3px56gepu8rzlsp4c1dpc0fx7"
            },
            "event_timestamp": 1615304991643,
            "initiating_entity": "policy",
            "reason_admin": {
                "en": "User left trusted network: CorpNet3"
            },
            "reason_user": {
                "en": "You're no longer connected to a trusted network.",
                "it": "Non sei più connesso a una rete attendibile."
            },

            "claims": {
                "trusted_network": "false"
            }
        }
    }
}
~~~
{: #token-claims-change-example-oidc-optional title="Example: OIDC ID Token Claims Change - Optional claims"}

~~~json
{
    "iss": "https://idp.example.com/987654321/",
    "jti": "dae94fed5f459881efa38b65c6772ddc",
    "iat": 1615305159,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
            "subject": {
                "format": "saml_assertion_id",
                "issuer": "https://idp.example.com/987654321/",
                "assertion_id": "_a75adf55-01d7-dbd8372ebdfc"
            },
            "event_timestamp": 1615304991643,
            "claims": {
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role": "ro-admin"
            }
        }
    }
}
~~~
{: #token-claims-change-example-saml title="Example: SAML Assertion Claims Change - Required claims only"}


## Credential Change {#credential-change}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/credential-change`

The Credential Change event signals that a credential was created, changed, 
revoked or deleted. Credential Change scenarios include:

  - password/PIN change/reset
  - certificate enrollment, renewal, revocation and deletion
  - second factor / passwordless credential enrollment or deletion (U2F, FIDO2, OTP, app-based)

The actual reason why the credential change occurred might be specified with the 
nested `reason_admin` and/or `reason_user` claims made in {{optional-event-claims}}.

### Event-Specific Claims {#credential-change-claims}

credential_type
: REQUIRED, JSON string: This MUST be one of the following strings, or any other
credential type supported mutually by the Transmitter and the Receiver.

    - `password`
    - `pin`
    - `x509`
    - `fido2-platform`
    - `fido2-roaming`
    - `fido-u2f`
    - `verifiable-credential`
    - `phone-voice`
    - `phone-sms`
    - `app`

change_type
: REQUIRED, JSON string: This MUST be one of the following strings:

    - `create`
    - `revoke`
    - `update`
    - `delete`

friendly_name
: OPTIONAL, JSON string: credential friendly name

x509_issuer
: OPTIONAL, JSON string: issuer of the X.509 certificate as defined in {{RFC5280}}

x509_serial
: OPTIONAL, JSON string: serial number of the X.509 certificate as defined in {{RFC5280}}

fido2_aaguid
: OPTIONAL, JSON string: FIDO2 Authenticator Attestation GUID as defined in {{WebAuthn}}

When `event_timestamp` is included, its value MUST represent the time at which
the credential change occurred.

### Examples  {#credential-change-examples}

NOTE: The event type URI is wrapped, the backslash is the continuation character.

~~~json
{
    "iss": "https://idp.example.com/3456789/",
    "jti": "07efd930f0977e4fcc1149a733ce7f78",
    "iat": 1615305159,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/credential-change": {
            "subject": {
                "format": "iss_sub",
                "iss": "https://idp.example.com/3456789/",
                "sub": "jane.smith@example.com"
            },
            "credential_type": "fido2-roaming",
            "change_type": "create",
            "fido2_aaguid": "accced6a-63f5-490a-9eea-e59bc1896cfc",
            "friendly_name": "Jane's USB authenticator",
            "initiating_entity": "user",
            "reason_admin": {
                "en": "User self-enrollment"
            },
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #credential-change-example-fido2 title="Example: Provisioning a new FIDO2 authenticator - Simple Subject + optional claims"}

## Assurance Level Change {#assurance-level-change}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/assurance-level-change`

The Assurance Level Change event signals that there has been a change in 
authentication method since the initial user login. This change can be from 
a weak authentication method to a strong authentication method, or vice versa. 

In the first scenario, Assurance Level Change will an increase, while in the 
second scenario it will be a decrease. For example, a user can start a session 
with Service Provider A using single factor authentication (such as a password). 
The user can then open another session with Service Provider B using 
two-factor authentication (such as OTP). In this scenario an increase 
Assurance Level Change event will signal to Service Provider A that user has 
authenticated with a stronger authentication method.

The actual reason why the assurance level changed might be specified with the 
nested `reason_admin` and/or `reason_user` claims made in {{optional-event-claims}}.

### Event-Specific Claims {#assurance-level-change-claims}

namespace:
: REQUIRED, JSON string: the namespace of the values in the `current_level` and `previous_level` claims.
This string MAY be one of the following strings:

  - `RFC8176`: The assurance level values are from the {{RFC8176}} specification
  - `RFC6711`: The assurance level values are from the {{RFC6711}} specification
  - `ISO-IEC-29115`: The assurance level values are from the {{ISO-IEC-29115}} specification
  - `NIST-IAL`: The assurance level values are from the {{NIST-IDPROOF}} specification
  - `NIST-AAL`: The assurance level values are from the {{NIST-AUTH}} specification
  - `NIST-FAL`: The assurance level values are from the {{NIST-FED}} specification
  - Any other value that is an alias for a custom namespace agreed between the Transmitter and the Receiver

current_level
: REQUIRED, JSON string: The current assurance level, as defined in the specified `namespace`

previous_level
: OPTIONAL, JSON string: the previous assurance level, as defined in the specified `namespace`
If the Transmitter omits this value, the Receiver MUST assume that the previous assurance level is unknown to the Transmitter

change_direction
: OPTIONAL, JSON string: the assurance level increased or decreased
If the Transmitter has specified the `previous_level`, then the Transmitter SHOULD provide a value for this claim.
If present, this MUST be one of the following strings:

  - `increase`
  - `decrease`

When `event_timestamp` is included, its value MUST represent the time at which
the assurance level changed.

### Examples  {#assurance-level-change-examples}

~~~json
{
    "iss": "https://idp.example.com/3456789/",
    "jti": "07efd930f0977e4fcc1149a733ce7f78",
    "iat": 1615305159,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change": {
            "subject": {
                "format": "iss_sub",
                "iss": "https://idp.example.com/3456789/",
                "sub": "jane.smith@example.com"
            },
            "namespace": "NIST-AAL",
            "current_level": "nist-aal2",
            "previous_level": "nist-aal1",
            "change_direction": "increase",
            "initiating_entity": "user",
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #assurance-level-change-examples-al-increase title="Example: Assurance Level Increase - Simple Subject + optional claims"}

~~~json
{
    "iss": "https://idp.example.com/3456789/",
    "jti": "07efd930f0977e4fcc1149a733ce7f78",
    "iat": 1615305159,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change": {
            "subject": {
                "format": "iss_sub",
                "iss": "https://idp.example.com/3456789/",
                "sub": "jane.smith@example.com"
            },
            "namespace": "Retinal Scan",
            "current_level": "hi-res-scan",
            "initiating_entity": "user",
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #assurance-level-change-examples-custom title="Example: Custom Assurance Level - Simple Subject"}


## Device Compliance Change {#device-compliance-change}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/device-compliance-change`

Device Compliance Change signals that a device's compliance status has changed.

The actual reason why the status change occurred might be specified with the 
nested `reason_admin` and/or `reason_user` claims made in {{optional-event-claims}}.

### Event-Specific Claims {#device-compliance-change-claims}

previous_status
: REQUIRED, JSON string: the compliance status prior to the change that triggered the event
: This MUST be one of the following strings:

  - `compliant`
  - `not-compliant`

current_status
: REQUIRED, JSON string: the current status that triggered the event
: This MUST be one of the following strings:

  - `compliant`
  - `not-compliant`

When `event_timestamp` is included, its value MUST represent the time at which
the device compliance status changed.

### Examples  {#device-compliance-change-examples}

NOTE: The event type URI is wrapped, the backslash is the continuation character.

~~~json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1615305159,
    "aud": "https://sp.example.com/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change": {
            "subject": {
                "device": {
                    "format": "iss_sub",
                    "iss": "https://idp.example.com/123456789/",
                    "sub": "e9297990-14d2-42ec-a4a9-4036db86509a"
                },
                "tenant": {
                    "format": "opaque",
                    "id": "123456789"
                }
            },
            "current_status": "not-compliant",
            "previous_status": "compliant",
            "initiating_entity": "policy",
            "reason_admin": {
                "en": "Location Policy Violation: C076E8A3"
            },
            "reason_user": {
                "en": "Device is no longer in a trusted location."
            },
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #device-compliance-change-examples-out-of-compliance title="Example: Device No Longer Compliant - Complex Subject + optional claims"}

--- back
# Acknowledgements

The authors wish to thank all members of the OpenID Foundation Shared Signals
Working Group who contributed to the development of this
specification.

# Notices

Copyright (c) 2021 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.
