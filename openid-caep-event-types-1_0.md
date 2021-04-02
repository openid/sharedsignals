---
title: OpenID CAEP Event Types 1.0
abbrev: CAEP-Event-Types
docname: openid-caep-event-types-1_0
date: 2021-04-02

ipr: none
cat: std
wg: Shared Signals and Events

coding: us-ascii
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author:
      -
        ins: T. Cappalli
        name: Tim Cappalli
        org: Microsoft
        email: tim.cappalli@microsoft.com
      -
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
        org: Google
        email: atultulshi@google.com

normative:
  RFC2119:
  RFC2616:
  SSE-PROFILE:
    target: http://openid.net/specs/openid-risc-profile-1_0.html
    title: OpenID Shared Signals and Events Profile of IETF Security Events 1.0
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
    date: 2021
  RFC8417:
  RFC8174:
  RFC5280:
  SP800-63R3:
    target: https://pages.nist.gov/800-63-3/sp800-63-3.html
    title: "NIST Special Publication 800-63: Digital Identity Guidelines"
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
  WebAuthn: 
    target: https://www.w3.org/TR/webauthn/
    title: "Web Authentication: An API for accessing Public Key Credentials Level 1"
    author: 
      -
        ins: D. Balfanz
        name: Dirk Balfanz
        org: Google


--- abstract

This document defines the Continuous Access Evaluation Protocol (CAEP) 
Event Types for the Shared Signals and Events Profile of IETF Security 
Events 1.0 {{SSE-PROFILE}}.

Event Types are introduced and defined in Security Event Token (SET) {{RFC8417}}.

--- middle

# Introduction {#introduction}

This specification is based on the Shared Signals and Events Profile 
of IETF Security Events 1.0 {{SSE-PROFILE}} and uses the subject identifiers 
defined there.

## Notational Considerations
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", 
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this 
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} 
when, and only when, they appear in all capitals, as shown here.

# Optional Event Claims {#optional-event-claims}
The following claims are optional unless otherwise specified in the event
definition.

event_timestamp
: REQUIRED, JSON number: the time at which the event described by this SET
  occurred. Its value is a JSON number representing the number of seconds 
  from 1970-01-01T0:0:0Z as measured in UTC until the date/time.

initiating_entity
: OPTIONAL, JSON string: describes the entity that invoked the event.
: Potential options:

  - `admin`:    an administrative action triggered the event

  - `user`:     an end-user action triggered the event

  - `policy`:   a policy evaluation triggered the event

  - `system`:   a system or platform assertion triggered the event

reason_admin
: OPTIONAL, JSON string: an administrative message for logging and auditing

reason_user
: OPTIONAL, JSON string: a user-friendly message for display to an end-user


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
        "https://schemas.openid.net/secevent/caep/event-type/\
        session-revoked": {
            "subject": {
                "format": "opaque",
                "sub": "dMTlD|1600802906337.16|16008.16"
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
        "https://schemas.openid.net/secevent/caep/event-type/\
        session-revoked": {
            "subject": {
                "session": {
                  "format": "opaque",
                  "sub": "dMTlD|1600802906337.16|16008.16"
                },
                "user": {
                  "format": "iss_sub",
                  "iss": "https://idp.example.com/123456789/",
                  "sub": "dMTlD|1600802906337.16|16008.16"
                },
                "tenant": {
                  "format": "opaque",
                  "id": "123456789"
                }
            },
            "initiating_entity": "policy",
            "reason_admin": "Landspeed Policy Violation: C076E82F",
            "reason_user": "Access attempt from multiple regions.",
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #session-revoked-example-session-id title="Example: Session Revoked - Complex Subject describing user + session ID + device (includes optional claims)"}

~~~ json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1615305159,
    "aud": "https://sp.example.com/caep",
    "sub": "jane.smith@example.com",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/\
        session-revoked": {
            "initiating_entity": "policy",
            "reason_admin": "Landspeed Policy Violation: C076E82F",
            "reason_user": "Access attempt from multiple regions.",
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
        "https://schemas.openid.net/secevent/caep/event-type/\
        session-revoked": {
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
            "reason_admin": "Policy Violation: C076E82F",
            "reason_user": "This device is no longer compliant.",
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
        "https://schemas.openid.net/secevent/caep/event-type/\
        token-claims-change": {
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
        "https://schemas.openid.net/secevent/caep/event-type/\
        token-claims-change": {
            "subject": {
                "format": "jwt_id",
                "iss": "https://idp.example.com/987654321/",
                "jti": "f61t6e20zdo3px56gepu8rzlsp4c1dpc0fx7"
            },
            "event_timestamp": 1615304991643,
            "initiating_entity": "policy",
            "reason_admin": "User left trusted network: CorpNet3",
            "reason_user": "You're no longer connected to a trusted network.",
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
        "https://schemas.openid.net/secevent/caep/event-type/\
        token-claims-change": {
            "subject": {
                "format": "saml_assertion_id",
                "issuer": "https://idp.example.com/987654321/",
                "assertion_id": "_a75adf55-01d7-dbd8372ebdfc"
            },
            "event_timestamp": 1615304991643,
            "claims": {
                "http://schemas.xmlsoap.org/ws/2005/05/identity/\
                claims/role": "ro-admin"
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
: REQUIRED, JSON string: potential options:
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
    - other mutually supported credential type

change_type
: REQUIRED, JSON string: potential options:
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
        "https://schemas.openid.net/secevent/caep/event-type/\
        credential-change": {
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
            "reason_admin": "User self-enrollment",
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

current_level
: REQUIRED, JSON string: the current NIST Authenticator Assurance Level (AAL) as defined in {{SP800-63R3}}
: Potential options:

  - `nist-aal1`
  - `nist-aal2`
  - `nist-aal3`

previous_level
: REQUIRED, JSON string: the previous NIST Authenticator Assurance Level (AAL) as defined in {{SP800-63R3}}
: Potential options:

  - `nist-aal1`
  - `nist-aal2`
  - `nist-aal3`

change_direction
: REQUIRED, JSON string: the Authenticator Assurance Level increased or decreased
: Potential options:
  - `increase`
  - `decrease`

When `event_timestamp` is included, its value MUST represent the time at which
the assurance level changed.


### Examples  {#assurance-level-change-examples}

NOTE: The event type URI is wrapped, the backslash is the continuation character.

~~~json
{
    "iss": "https://idp.example.com/3456789/",
    "jti": "07efd930f0977e4fcc1149a733ce7f78",
    "iat": 1615305159,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/\
        assurance-level-change": {
            "subject": {
                "format": "iss_sub",
                "iss": "https://idp.example.com/3456789/",
                "sub": "jane.smith@example.com"
            },
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


## Device Compliance Change {#device-compliance-change}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/device-compliance-change`

Device Compliance Change signals that a device's compliance status has changed.

The actual reason why the status change occurred might be specified with the 
nested `reason_admin` and/or `reason_user` claims made in {{optional-event-claims}}.

### Event-Specific Claims {#device-compliance-change-claims}

previous_status
: REQUIRED, JSON string: the compliance status prior to the change that triggered the event
: Potential options:

  - `compliant`
  - `not-compliant`

current_status
: REQUIRED, JSON string: the current status that triggered the event
: Potential options:

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
        "https://schemas.openid.net/secevent/caep/event-type/\
        device-compliance-change": {
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
            "reason_admin": "Location Policy Violation: C076E82F",
            "reason_user": "Device is no longer in a trusted location.",
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #device-compliance-change-examples-out-of-compliance title="Example: Device No Longer Compliant - Complex Subject + optional claims"}

--- back