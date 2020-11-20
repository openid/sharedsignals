%%%
title = "OpenID CAEP Event Types 1.0"
docname = "draft-openid-caep-event-types-01"
ipr = "none"
area = "Security"
workgroup = "Shared Signals and Events Working Group"
submissiontype = "independent"
category = "info"
keyword = [""]
date = 2020-11-20T12:00:00Z

[seriesInfo]
name = "Internet-Draft"
value = "openid-caep-event-types-1_0"
status = "informational"


[[author]]
initials="T."
surname="Cappalli"
fullname="Tim Cappalli"
abbrev="Microsoft"
organization="Microsoft"
  [author.address]
  email = "tim.cappalli+caep@microsoft.com"

[[author]]
initials="A."
surname="Tulshibagwale"
fullname="Atul Tulshibagwale"
abbrev="Google"
organization="Google"
  [author.address]
  email = "atultulshi@google.com"
%%%

.# Abstract

This document defines the Continous Access Evaluation Protocol (CAEP) Event Types. Event Types are introduced and defined in Security Event Token [@SET]

{mainmatter}

# Introduction

This specification is based on SSE Profile [@SSE-PROFILE] and uses the subject 
identifiers defined there.

## Notational Considerations
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", 
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this 
document are to be interpreted as described in BCP 14 [@RFC2119] [@RFC8174] 
when, and only when, they appear in all capitals, as shown here.

# Event Types {#event-types}
The base URI for CAEP event types is:
<br />
`https://schemas.openid.net/secevent/caep/event-type/`

## Session Revoked {#session-revoked}
Event Type URI:
<br />
`https://schemas.openid.net/secevent/caep/event-type/session-revoked`

Session Revoked signals that the session identified by the subject has been 
revoked. 

The actual reason why the session was revoked might be specified with the 
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#session-revoked-attributes}

`event_timestamp`
: REQUIRED, JSON number: the time at which the session revocation occured.
Its value is a JSON number representing the number of seconds from 
1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
be less than or equal to the "iat" claim in the parent 
Security Event Token (SET).

`initiating_entity`
: OPTIONAL, JSON string: describes the entity that invoked the session revocation.

    Potential options:

    * `admin`:    an administrator revoked the session
    * `user`:     the end-user revoked the session
    * `policy`:   a policy evaluation resulted in the session revocation
    * `system`:   a system or platform assertion resulted in the session revocation

`reason_admin`
: OPTIONAL, JSON string: an administrative message for logging and auditing

`reason_user`
: OPTIONAL, JSON string: a user-friendly message for display to an end-user

`tenant_id`
: OPTIONAL, JSON string: tenant identifier

### Examples  {#session-revoked-examples}

~~~ json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1600976590,
    "aud": "https://sp.example.com/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/\
        session-revoked": {
            "subject": {
                "subject_type": "user-device-session",
                "session": {
                  "iss": "https://idp.example.com/123456789/",
                  "sub": "dMTlD|1600802906337.16|16008.16"
                }
            },
            "initiating_entity": "policy",
            "reason_admin": "Policy Violation: C076E82F",
            "reason_user": "Landspeed violation.",
            "tenant_id": "123456789",
            "event_timestamp": 1600975810
        }
    }
}
~~~
Figure: Example: Session Revoked for Session ID

~~~ json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1600976590,
    "aud": "https://sp.example.com/caep",
    "sub": "jane.smith@example.com",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/\
        session-revoked": {
            "initiating_entity": "policy",
            "reason_admin": "Policy Violation: C076E82F",
            "reason_user": "Landspeed violation.",
            "tenant_id": "123456789",
            "event_timestamp": 1600975810
        }
    }
}
~~~
Figure: Example: Session Revoked for User using sub claim

~~~json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1600976590,
    "aud": "https://sp.example.com/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
            "subject": {
                "subject_type": "user-device-session",
                "user": {
                    "subject_type": "iss-sub",
                    "iss": "https://idp.example.com/123456789/",
                    "sub": "jane.smith@example.com"
                },
                "device": {
                    "subject_type": "iss-sub",
                    "iss": "https://idp.example.com/123456789/",
                    "sub": "e9297990-14d2-42ec-a4a9-4036db86509a"
                }
            },
            "initiating_entity": "policy",
            "reason_admin": "Policy Violation: C076E82F",
            "reason_user": "Your device is no longer compliant.",
            "tenant_id": "123456789",
            "event_timestamp": 1600975810
        }
    }
}
~~~
Figure: Example: Session Revoked for User + Device


## Token Claims Change {#token-claims-change}
Event Type URI:
<br />
`https://schemas.openid.net/secevent/caep/event-type/token-claims-change`

Token Claims Change signals that a claim in a token specified in the subject 
has changed.

The actual reason why the claims change occured might be specified with the 
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#session-revoked-attributes}

`event_timestamp`
: REQUIRED JSON number: the time at which the claims change occured.
Its value is a JSON number representing the number of seconds from 
1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
be less than or equal to the "iat" claim in the parent 
Security Event Token (SET).

`initiating_entity`
: OPTIONAL, JSON string: describes the entity that invoked the session revocation.

    Potential options:

    * `admin`:    an administrator revoked the session
    * `user`:     the end-user revoked the session
    * `policy`:   a policy evaluation resulted in the session revocation
    * `system`:   a system or platform assertion resulted in the session revocation

`reason_admin`
: OPTIONAL, JSON string: an administrative message for logging and auditing

`reason_user`
: OPTIONAL, JSON string: a user-friendly message for display to an end-user

`tenant_id`
: OPTIONAL, JSON string: tenant identifier

### Examples  {#token-claims-change-examples}

~~~ json
{
    "iss": "https://idp.example.com/987654321/",
    "jti": "9afce1e4e642b165fcaacdd0e7aa4903",
    "iat": 1600976590,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/\
        token-claims-change": {
            "subject": {
                "subject_type": "jwt-id",
                "iss": "https://idp.example.com/987654321/",
                "jti": "f61t6e20zdo3px56gepu8rzlsp4c1dpc0fx7"
            },
            "event_timestamp": 1600975810,
            "claims": {
                "role": "ro-admin"
            }
        }
    }
}
~~~
Figure: Example: OIDC ID Token Claims Change

~~~json
{
    "iss": "https://idp.example.com/987654321/",
    "jti": "dae94fed5f459881efa38b65c6772ddc",
    "iat": 1600976590,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/\
        token-claims-change": {
            "subject": {
                "subject_type": "saml-assertion-id",
                "issuer": "https://idp.example.com/987654321/",
                "assertion_id": "_a75adf55-01d7-dbd8372ebdfc"
            },
            "event_timestamp": 1600975810,
            "claims": {
                "http://schemas.xmlsoap.org/ws/2005/05/identity/\
                claims/role": "ro-admin"
            }
        }
    }
}
~~~
Figure: Example: SAML Assertion Claims Change


## Credential Change {#credential-change}
Event Type URI:
<br />
`https://schemas.openid.net/secevent/caep/event-type/credential-change`

The Credential Change event signals that a credential was created, changed, 
revoked or deleted. Credential change scenarios include:

  * password/PIN change/reset
  * certificate enrollment, renewal, revocation and deletion
  * second factor / passwordless credential enrollment and deletion (U2F, FIDO2, OTP, app-based)

The actual reason why the credential change occured might be specified with the 
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#credential-change-attributes}

`event_timestamp`
: REQUIRED, JSON number: the time at which the claims change occured.
Its value is a JSON number representing the number of seconds from 
1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
be less than or equal to the "iat" claim in the parent 
Security Event Token (SET).

`current_level`
: REQUIRED, JSON string: the current NIST Authenticator Assurance Level (AAL) as defined in [@SP800-63R3]

  Options:

  * nist-aal1
  * nist-aal2
  * nist-aal3

`previous_level`
: REQUIRED, JSON string: the previous NIST Authenticator Assurance Level (AAL) as defined in [@SP800-63R3]

  Options:

  * nist-aal1
  * nist-aal2
  * nist-aal3

`change_direction`
: REQUIRED, JSON string: the Authenticator Assurance Level increased or decreased

  Options:
  * increase
  * decrease

`credential_type`
: OPTIONAL, JSON string: potential options:
  * password
  * pin
  * x509
  * fido2-platform
  * fido2-roaming
  * fido-u2f
  * verifiable-credential
  * phone-voice
  * phone-sms
  * app
  * &lt;other mutually supported credential type&gt;

`change_type`
: REQUIRED, JSON string: potential options:
  * create
  * revoke
  * update
  * delete

`initiating_entity`
: OPTIONAL, JSON string: describes the entity that invoked the session revocation.

    Potential options:

    * `admin`:    an administrator revoked the session
    * `user`:     the end-user revoked the session
    * `policy`:   a policy evaluation resulted in the session revocation
    * `system`:   a system or platform assertion resulted in the session revocation

`reason_admin`
: OPTIONAL, JSON string: an administrative message for logging and auditing

`reason_user`
: OPTIONAL, JSON string: a user-friendly message for display to an end-user

`tenant_id`
: OPTIONAL, JSON string: tenant identifier

`friendly_name`
: OPTIONAL, JSON string: credential friendly name

`x509_issuer`
: OPTIONAL, JSON string: issuer of the X.509 certificate as defined in [@RFC5280]

`x509_serial`
: OPTIONAL, JSON string: serial number of the X.509 certificate as defined in [@RFC5280]

`fido2_aaguid`
: OPTIONAL, JSON string: FIDO2 Authenticator Attestation GUID as defined in [@WebAuthn]
            

### Examples  {#credential-change-examples}


~~~json
{
    "iss": "https://idp.example.com/3456789/",
    "jti": "07efd930f0977e4fcc1149a733ce7f78",
    "iat": 1600976598,
    "aud": "https://sp.example2.net/caep",
    "events": {
        "https://schemas.openid.net/secevent/caep/event-type/\
        credential-changed": {
            "subject": {
                "subject_type": "iss-sub",
                "iss": "https://idp.example.com/3456789/",
                "sub": "jane.smith@example.com"
            },
            "current_level": "nist-aal2",
            "previous_level": "nist-aal1",
            "change_direction": "increase",
            "credential_type": "fido2-roaming",
            "change_type": "create",
            "fido2_aaguid": "accced6a-63f5-490a-9eea-e59bc1896cfc",
            "credential_name": "Jane's USB authenticator",
            "initiating_entity": "user",
            "event_timestamp": 1600975811
        }
    }
}
~~~
Figure: Example: Provisioning a new FIDO2 authenticator

## Device Compliance Change {#device-compliance-change}
Event Type URI:
<br />
`https://schemas.openid.net/secevent/caep/event-type/device-compliance-change`

Token Claims Change signals that a claim in a token specified in the subject 
has changed.

The actual reason why the claims change occured might be specified with the 
nested `reason_admin` and/or `reason_user` attributes described below.

### Attributes {#session-revoked-attributes}

`event_timestamp`
: REQUIRED, JSON number: the time at which the claims change occured.
Its value is a JSON number representing the number of seconds from 
1970-01-01T0:0:0Z as measured in UTC until the date/time. This value must 
be less than or equal to the "iat" claim in the parent 
Security Event Token (SET).

`previous_status`
: REQUIRED, JSON string: the compliance status prior to the change that triggered the event
  
    Options:

    * compliant
    * not-compliant

`current_status`
: REQUIRED, JSON string: the current status that triggered the event
  
    Options:

    * compliant
    * not-compliant

`initiating_entity`
: OPTIONAL, JSON string: describes the entity that invoked the session revocation

    Potential options:

    * `admin`:    an administrator revoked the session
    * `user`:     the end-user revoked the session
    * `policy`:   a policy evaluation resulted in the session revocation
    * `system`:   a system or platform assertion resulted in the session revocation

`reason_admin`
: OPTIONAL, JSON string: an administrative message for logging and auditing

`reason_user`
: OPTIONAL, JSON string: a user-friendly message for display to an end-user

`tenant_id`
: OPTIONAL, JSON string: tenant identifier

### Examples  {#device-compliance-change-examples}

~~~json
{
    "iss": "https://idp.example.com/123456789/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1600976590,
    "aud": "https://sp.example.com/caep",
    "events": {
         "https://schemas.openid.net/secevent/caep/event-type/\
         session-revoked": {
            "subject_type": "user-device-session",
            "device": {
                "subject_type": "iss-sub",
                "iss": "https://idp.example.com/123456789/",
                "sub": "e9297990-14d2-42ec-a4a9-4036db86509a"
            }
        },
        "current_status": "not-compliant",
        "previous_status": "compliant",
        "initiating_entity": "policy",
        "reason_admin": "Location Policy Violation: C076E82F",
        "reason_user": "Device is no longer in a trusted location.",
        "tenant_id": "123456789",
        "event_timestamp": 1600975810
    }
}
~~~
Figure: Example: Device has gone out of compliance


# Additional Examples

to do 



{backmatter}

<reference anchor="JSON" target='https://www.rfc-editor.org/info/rfc7159'>
  <front>
    <title>The JavaScript Object Notation (JSON) Data Interchange Format</title>
    <author initials='T.' surname='Bray' fullname='T. Bray' role='editor'>
      <organization />
    </author>
    <date year='2014' month='March' />
    <abstract>
      <t>JavaScript Object Notation (JSON) is a lightweight, text-based, language-independent data interchange format.  It was derived from the ECMAScript Programming Language Standard.  JSON defines a small set of formatting rules for the portable representation of structured data.</t>
      <t>This document removes inconsistencies with other specifications of JSON, repairs specification errors, and offers experience-based interoperability guidance.</t>
    </abstract>
  </front>
  <seriesInfo name='RFC' value='7159'/>
  <seriesInfo name='DOI' value='10.17487/RFC7159'/>
</reference>
<reference anchor="SET" target="https://tools.ietf.org/html/draft-ietf-secevent-token-09">
  <front>
    <title>Security Event Token (SET)</title>
    <author fullname="Phil Hunt" initials="P." role="editor" surname="Hunt">
      <organization />
    </author>
    <author fullname="Michael B. Jones" initials="M.B." surname="Jones">
      <organization />
    </author>
    <author fullname="William Denniss" initials="W." surname="Denniss">
      <organization />
    </author>
    <author fullname="Morteza Ansari" initials="M.A." surname="Ansari">
      <organization />
    </author>
    <date year="2018" month="April" />
  </front>
</reference>
<reference anchor="RFC2119" target='https://www.rfc-editor.org/info/rfc2119'>
  <front>
    <title>Key words for use in RFCs to Indicate Requirement Levels</title>
    <author initials='S.' surname='Bradner' fullname='S. Bradner'>
      <organization />
    </author>
    <date year='1997' month='March' />
    <abstract>
      <t>In many standards track documents several words are used to signify the requirements in the specification.  These words are often capitalized. This document defines these words as they should be interpreted in IETF documents.  This document specifies an Internet Best Current Practices for the Internet Community, and requests discussion and suggestions for improvements.</t>
    </abstract>
  </front>
  <seriesInfo name='BCP' value='14'/>
  <seriesInfo name='RFC' value='2119'/>
  <seriesInfo name='DOI' value='10.17487/RFC2119'/>
</reference>
<reference anchor="RFC8174" target="https://www.rfc-editor.org/info/rfc8174">
  <front>
    <title>Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words</title>
    <author initials="B." surname="Leiba" fullname="B. Leiba">
      <organization/>
    </author>
    <date year="2017" month="May"/>
    <abstract>
      <t>RFC 2119 specifies common key words that may be used in protocol specifications. This 
          document aims to reduce the ambiguity by clarifying that only UPPERCASE usage of the 
          key words have the defined special meanings.</t>
    </abstract>
  </front>
  <seriesInfo name="BCP" value="14"/>
  <seriesInfo name="RFC" value="8174"/>
  <seriesInfo name="DOI" value="10.17487/RFC8174"/>
</reference>
<reference anchor="SSE-PROFILE" target="http://openid.net/specs/openid-risc-profile-1_0.html">
  <front>
    <title>OpenID Shared Signals and Events Profile of IETF Security Events 2.0</title>
    <author initials="A." surname="Tulshibagwale" fullname="Atul Tulshibagwale">
      <organization abbrev="Google">Google</organization>
    </author>
    <author initials="T." surname="Cappalli" fullname="Tim Cappalli">
      <organization abbrev="Microsoft">Microsoft</organization>
    </author>
    <date year="2018" month="April" />
  </front>
</reference>
<reference anchor="WebAuthn" target="https://www.w3.org/TR/webauthn/">
  <front>
    <title>Web Authentication: An API for accessing Public Key Credentials Level 1</title>
    <author initials="D." surname="Balfanz" fullname="Dirk Balfanz">
      <organization abbrev="Google">Google</organization>
    </author>
    <date year="2018" month="March" />
  </front>
</reference>

<reference anchor="RFC5280" target='https://tools.ietf.org/html/rfc5280'>
  <front>
    <title>Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile</title>
    <author initials='D.' surname='Cooper' fullname='D. Cooper'>
      <organization abbrev="NIST">NIST</organization>
    </author>
    <author initials='S.' surname='Santesson' fullname='S. Santesson'>
      <organization abbrev="Microsoft">Microsoft</organization>
    </author>
    <author initials='S.' surname='Farrell' fullname='S. Farrell'>
      <organization abbrev="Trinity College Dublin">Trinity College Dublin</organization>
    </author>
    <author initials='S.' surname='Boeyen' fullname='S. Boeyen'>
      <organization abbrev="Entrust">Entrust</organization>
    </author>
    <author initials='R.' surname='Housley' fullname='R. Housley'>
      <organization abbrev="Vigil Security">Vigil Security</organization>
    </author>
    <author initials='W.' surname='Polk' fullname='W. Polk'>
      <organization abbrev="NIST">NIST</organization>
    </author>
    <date year='2008' month='May' />
  </front>
</reference>
<reference anchor="SP800-63R3" target="https://pages.nist.gov/800-63-3/sp800-63-3.html">
  <front>
    <title>NIST Special Publication 800-63: Digital Identity Guidelines</title>
    <author initials="P." surname="Grassi" fullname="Paul Grassi">
      <organization />
    </author>
    <author initials="M." surname="Garcia" fullname="Michael Garcia">
      <organization />
    </author>
    <author initials="J." surname="Fenton" fullname="James Fenton">
      <organization />
    </author>
    <date year="2017" month="June" />
  </front>
</reference>