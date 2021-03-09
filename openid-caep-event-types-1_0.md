---
title: OpenID CAEP Event Types 1.0
abbrev: CAEP-Event-Types
docname: openid-caep-event-types-1_0
date: 2021-03-09

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

This document defines the Continous Access Evaluation Protocol (CAEP) 
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
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#session-revoked-attributes}

event_timestamp
: REQUIRED, JSON number: the time at which the session revocation occured.
  Its value is a JSON number representing the number of milliseconds from 
  1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
  be less than or equal to the "iat" claim in the parent 
  Security Event Token (SET).

initiating_entity
: OPTIONAL, JSON string: describes the entity that invoked the session revocation.
: Potential options:
  - `admin`:    an administrator revoked the session
  - `user`:     the end-user revoked the session
  - `policy`:   a policy evaluation resulted in the session revocation
  - `system`:   a system or platform assertion resulted in the session revocation

reason_admin
: OPTIONAL, JSON string: an administrative message for logging and auditing

reason_user
: OPTIONAL, JSON string: a user-friendly message for display to an end-user


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
{: #session-revoked-example-session-id title="Example: Session Revoked for User + Session ID + Tenant (Complex Subject)"}

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
{: #session-revoked-example-user-sub title="Example: Session Revoked for User using sub claim"}

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
{: #session-revoked-example-user-device title="Example: Session Revoked for User + Device + Tenant (Complex Subject)"}

## Token Claims Change {#token-claims-change}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/token-claims-change`

Token Claims Change signals that a claim in a token, identified by the 
subject claim, has changed. 

The actual reason why the claims change occured might be specified with the 
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#token-claims-change-attributes}

event_timestamp
: REQUIRED, JSON number: the time at which the claims change occured.
  Its value is a JSON number representing the number of milliseconds from 
  1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
  be less than or equal to the "iat" claim in the parent 
  Security Event Token (SET).

claims
: REQUIRED, JSON object: one or more claims with their new value(s)

initiating_entity
: OPTIONAL, JSON string: describes the entity that invoked the token claims change
: Potential options:
  - `admin`:    an administrator invoked a token claims change
  - `user`:     the end-user invoked a token claims change
  - `policy`:   a policy evaluation resulted in the token claims change
  - `system`:   a system or platform assertion resulted in the the token claims change

reason_admin
: OPTIONAL, JSON string: an administrative message for logging and auditing

reason_user
: OPTIONAL, JSON string: a user-friendly message for display to an end-user


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
{: #token-claims-change-example-oidc title="Example: OIDC ID Token Claims Change"}


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
{: #token-claims-change-example-saml title="Example: SAML Assertion Claims Change"}


## Credential Change {#credential-change}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/credential-change`

The Credential Change event signals that a credential was created, changed, 
revoked or deleted. Credential Change scenarios include:

  - password/PIN change/reset
  - certificate enrollment, renewal, revocation and deletion
  - second factor / passwordless credential enrollment or deletion (U2F, FIDO2, OTP, app-based)

The actual reason why the credential change occured might be specified with the 
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#credential-change-attributes}

event_timestamp
: REQUIRED, JSON number: the time at which the credential change occured.
  Its value is a JSON number representing the number of milliseconds from 
  1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
  be less than or equal to the "iat" claim in the parent 
  Security Event Token (SET).

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

initiating_entity
: OPTIONAL, JSON string: describes the entity that invoked the credential change.
: Potential options:

  - `admin`:    an administrator changed the credential
  - `user`:     the end-user changed the credential
  - `policy`:   a policy evaluation resulted in the credential change
  - `system`:   a system or platform assertion resulted in credential change

reason_admin
: OPTIONAL, JSON string: an administrative message for logging and auditing

reason_user
: OPTIONAL, JSON string: a user-friendly message for display to an end-user

friendly_name
: OPTIONAL, JSON string: credential friendly name

x509_issuer
: OPTIONAL, JSON string: issuer of the X.509 certificate as defined in {{RFC5280}}

x509_serial
: OPTIONAL, JSON string: serial number of the X.509 certificate as defined in {{RFC5280}}

fido2_aaguid
: OPTIONAL, JSON string: FIDO2 Authenticator Attestation GUID as defined in {{WebAuthn}}
            

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
            "credential_name": "Jane's USB authenticator",
            "initiating_entity": "user",
            "reason_admin": "User self-enrollment",
            "event_timestamp": 1615304991643
        }
    }
}
~~~
{: #credential-change-example-fido2 title="Example: Provisioning a new FIDO2 authenticator"}

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
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#assurance-level-change-attributes}

event_timestamp
: REQUIRED, JSON number: the time at which the assurance level change occured.
  Its value is a JSON number representing the number of milliseconds from 
  1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
  be less than or equal to the "iat" claim in the parent 
  Security Event Token (SET).

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

initiating_entity
: OPTIONAL, JSON string: describes the entity that invoked the assurance level change
: Potential options:

  - `admin`:    an administrative action resulted in an assurance level change
  - `user`:     an end-user action resulted in an assurance level change
  - `policy`:   a policy evaluation resulted in an assurance level change
  - `system`:   a system or platform assertion resulted in an assurance level change

reason_admin
: OPTIONAL, JSON string: an administrative message for logging and auditing

reason_user
: OPTIONAL, JSON string: a user-friendly message for display to an end-user

            
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
{: #assurance-level-change-examples-al-increase title="Example: Assurance Level Increase"}


## Device Compliance Change {#device-compliance-change}
Event Type URI:

`https://schemas.openid.net/secevent/caep/event-type/device-compliance-change`

Device Compliance Change signals that a device's compliance status has changed.

The actual reason why the status change occured might be specified with the 
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#device-compliance-change-attributes}

event_timestamp
: REQUIRED, JSON number: the time at which the device compliance change 
  occured. Its value is a JSON number representing the number of milliseconds from 
  1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
  be less than or equal to the "iat" claim in the parent 
  Security Event Token (SET).

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

initiating_entity
: OPTIONAL, JSON string: describes the entity that invoked the device compliance change
: Potential options:

  - `admin`:    an administrative action invoked the device compliance change
  - `user`:     the end-user action invoked the device compliance change
  - `policy`:   a policy evaluation resulted in the device compliance change
  - `system`:   a system or platform assertion resulted in the device compliance change

reason_admin
: OPTIONAL, JSON string: an administrative message for logging and auditing

reason_user
: OPTIONAL, JSON string: a user-friendly message for display to an end-user


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
~~~
{: #device-compliance-change-examples-out-of-compliance title="Example: Device has gone out of compliance with a Complex Subject"}

--- back