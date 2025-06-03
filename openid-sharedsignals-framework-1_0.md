---
title: OpenID Shared Signals Framework Specification 1.0
abbrev: SharedSignals
docname: openid-sharedsignals-framework-1_0
date: 2025-06-03

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
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
        org: SGNL
        email: atul@sgnl.ai
      -
        ins: T. Cappalli
        name: Tim Cappalli
        org: Microsoft
        email: tim.cappalli@microsoft.com
      -
        ins: M. Scurtescu
        name: Marius Scurtescu
        org: Coinbase
        email: marius.scurtescu@coinbase.com
      -
        ins: A. Backman
        name: Annabelle Backman
        org: Amazon
        email: richanna@amazon.com
      -
        ins: J. Bradley
        name: John Bradley
        org: Yubico
        email: secevemt@ve7jtb.com
      -
        ins: S. Miel
        name: Shayne Miel
        org: Cisco
        email: smiel@cisco.com

contributor:
      -
        ins: S. Venema
        name: Steve Venema
        org: ForgeRock
        email: steve.venema@forgerock.com
        contribution: |
          Steve defined the format field of Complex Subjects
      -
        ins: A. Deshpande
        name: Apoorva Deshpande
        org: Okta
        email: apoorva.deshpande@okta.com
      -
        ins: S. O'Dell
        name: Sean O'Dell
        org: The Walt Disney Company
        email: sean.odentity@disney.com
      -
        ins: J. Schreiber
        name: Jen Schreiber
        org: Workday
        email: jennifer.winer@workday.com
      -
        ins: T. Raibhandare
        name: Tushar Raibhandare
        org: Google
        email: traib@google.com
      -
        ins: Y. Sarig
        name: Yair Sarig
        org: Omnissa
        email: ysarig@omnissa.com

normative:

  OpenID.Core:
    author:
    - ins: N. Sakimura
      name: Nat Sakimura
    - ins: J. Bradley
      name: John Bradley
    - ins: M.B. Jones
      name: Michael B. Jones
    - ins: B. de Medeiros
      name: Breno de Medeiros
    - ins: C. Mortimore
      name: Chuck Mortimore
    date: November 2014
    target: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    title: OpenID Connect Core 1.0 - ID Token
  OASIS.saml-core-2.0-os:
  RFC2119:
  RFC6749:
  RFC7159:
  RFC7517:
  RFC7519:
  RFC8174:
  RFC8417:
  RFC8615:
  RFC8935:
  RFC8936:
  RFC9110:
  RFC9493:
  RFC4001:
  RFC3986:
  CAEP:
    author:
    -
      ins: T. Cappalli
      name: Tim Cappalli
    -
      ins: A. Tulshibagwale
      name: Atul Tulshibagwale
    date: June 2024
    target: https://openid.net/specs/openid-caep-1_0.html
    title: OpenID Continuous Access Evaluation Profile 1.0
  RISC:
    author:
    -
      ins: M. Scurtescu
      name: Marius Scurtescu
    -
      ins: A. Backman
      name: Annabelle Backman
    -
      ins: P. Hunt
      name: Phil Hunt
    -
      ins: J. Bradley
      name: John Bradley
    -
      ins: S. Bounev
      name: Stan Bounev
    -
      ins: A. Tulshibagwale
      name: Atul Tulshibagwale
    date: April 2022
    target: https://openid.net/specs/openid-risc-profile-specification-1_0.html
    title: OpenID RISC Profile Specification 1.0
  NAMINGCONVENTION:
    author:
    - name: OpenID Foundation
    target: https://openid.net/wg/resources/naming-and-contents-of-specifications/
    title: OpenID Naming and Content of Specifications

--- abstract

This Shared Signals Framework (SSF) enables sharing of signals and events
between cooperating peers. It enables multiple applications such as Risk
Incident Sharing and Coordination (RISC) and the Continuous Access Evaluation
Profile ({{CAEP}})

This specification defines:

* A profile for Security Events Tokens {{RFC8417}}
* Subject principals
* Subject claims in SSF events
* Event types
* Events
* Transmitter Configuration Metadata and its discovery method for Receivers
* A management API for Event Streams

This specification also directly profiles several IETF Security Events
specifications:

* Security Event Token (SET) {{RFC8417}}
* Subject Identifiers for Security Event Tokens {{RFC9493}}
* Push-Based SET Token Delivery Using HTTP {{RFC8935}}
* Poll-Based SET Token Delivery Using HTTP {{RFC8936}}

--- middle

# Introduction {#introduction}

## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Subject Principals {#subject-principals}

This Shared Signals Framework specification defines a Subject Principal to be
the entities about which an event can be sent by Transmitters and received by
Receivers using the Shared Signals Framework.

Subject Principals are the managed entities in an SSF Transmitter or Receiver.
These include human or robotic principals, devices, customer tenants in a
multi-tenanted service, organizational units within a tenant, groups of subject
principals, or other entities that are managed by Transmitters and Receivers.
There may be other actors or resources that can be treated as Subject
Principals, and event-type definitions SHOULD specify the range of principals
addressed by the event.

Subject Principals are identified by Subject Members defined below.

# Subject Members in SSF Events {#subject-ids}

## Subject Members {#subject-members}

A Subject Member of an SSF event describes a subject of the event. A top-level
claimnamed `sub_id` MUST be used to describe the primary subject of the event.

### Existing CAEP and RISC Events

Event types already defined in the CAEP ({{CAEP}}) and RISC ({{RISC}})
specifications MAY use a `subject` field within the `events` claim of the SSF
event to describe the primary Subject Principal of the event. SSF Transmitters
MUST include the top-level `sub_id` claim even for these existing event types.

### New Event Types

New event types MUST use the top-level `sub_id` claim and MUST NOT use the
`subject` field in the `events` claim to describe the primary Subject Principal.

### Additional Subject Members

Specific event types MAY define additional Subject Members if required to
describe additional subjects of that event type (e.g. a Transferee). These
additional subject fields MAY have any field name.

### Subject Member Values

Each Subject Member MUST refer to exactly one Subject Principal. The value of a
Subject Member MAY be a "simple subject" or a "complex subject".

## Simple Subject Members {#simple-subjects}

A Simple Subject Member has a claim name and a value that is a "Subject
Identifier" as defined in the Subject Identifiers for Security Event Tokens
{{RFC9493}}. Below is a non-normative example of a Simple Subject Member in an
SSF event.

~~~ json
"sub_id": {
  "format": "email",
  "email": "foo@example.com"
}
~~~
{: #simple-subject-ex title="Example: Simple Subject"}

## Complex Subject Members {#complex-subjects}

A Complex Subject Member has a name and a value that is a JSON {{RFC7159}}
object that has a format field, and one or more Simple Subject Members. The name
of the format field is "format", and its value is "complex". The name of each
Simple Subject Member in this value MAY be one of the following:

user

> OPTIONAL. A Subject Identifier that identifies a user.

device

> OPTIONAL. A Subject Identifier that identifies a device.

session

> OPTIONAL. A Subject Identifier that identifies a session.

application

> OPTIONAL. A Subject Identifier that identifies an application.

tenant

> OPTIONAL. A Subject Identifier that identifies a tenant.

org_unit

> OPTIONAL. A Subject Identifier that identifies an organizational unit.

group

> OPTIONAL. A Subject Identifier that identifies a group.

Additional Subject Member names MAY be used in Complex Subjects. Each member
name MAY appear at most once in the Complex Subject value.

Below is a non-normative example of a Complex Subject claim in an SSF event.

~~~ json
"sub_id": {
  "format": "complex",
  "user" : {
    "format": "email",
    "email": "bar@example.com"
  },
  "tenant" : {
    "format": "iss_sub",
    "iss" : "https://example.com/idp1",
    "sub" : "1234"
  }
}
~~~
{: #complex-subject-ex title="Example: Complex Subject"}

### Complex Subject Interpretation {#complex-subject-interpretation}

All members within a Complex Subject MUST represent attributes of the same
Subject Principal. As a whole, the Complex Subject MUST refer to exactly one
Subject Principal.

For details about how to interpret unspecified claims in a Complex Subject as
wildcards, please see the section on Subject Matching ({{subject-matching}}).

## Subject Identifiers in SSF Events {#subject-ids-in-ssf}

A Subject Identifier in an SSF event MUST have an identifier format that is any
one of:

* Defined in the IANA Registry defined in Subject Identifiers for Security
Event Tokens {{RFC9493}}
* An identifier format defined in the Additional Subject Identifier Formats
({{additional-subject-id-formats}}) section below, OR
* A proprietary subject identifier format that is agreed to between parties.
Members within a subject identifier that has a proprietary subject identifier
format are agreed to between the parties and such agreement is outside the
scope of this specification.

## Additional Subject Identifier Formats {#additional-subject-id-formats}

The following new subject identifier formats are defined:

### JWT ID Subject Identifier Format {#sub-id-jwt-id}

The "JWT ID" Subject Identifier Format specifies a JSON Web Token (JWT)
identifier, defined in {{RFC7519}}. Subject Identifiers of this type MUST
contain the following members:

iss

> REQUIRED. The "iss" (issuer) claim of the JWT being identified, defined in
  {{RFC7519}}

jti

> REQUIRED. The "jti" (JWT token ID) claim of the JWT being identified, defined
  in {{RFC7519}}

The "JWT ID" Subject Identifier Format is identified by the name "jwt_id".

Below is a non-normative example of Subject Identifier for the "jwt_id" Subject
Identifier Format.

~~~ json
{
    "format": "jwt_id",
    "iss": "https://idp.example.com/123456789/",
    "jti": "B70BA622-9515-4353-A866-823539EECBC8"
}
~~~
{: #sub-id-jwtid title="Example: 'jwt_id' Subject Identifier"}

### SAML Assertion ID Subject Identifier Format {#sub-id-saml-assertion-id}

The "SAML Assertion ID" Subject Identifier Format specifies a SAML 2.0
{{OASIS.saml-core-2.0-os}} assertion identifier. Subject Identifiers of this
format MUST contain the following members:

issuer

> REQUIRED. The "Issuer" value of the SAML assertion being identified, defined
  in {{OASIS.saml-core-2.0-os}}

assertion_id

> REQUIRED. The "ID" value of the SAML assertion being identified, defined in
  {{OASIS.saml-core-2.0-os}}

The "SAML Assertion ID" Subject Identifier Format is identified by the name
"saml_assertion_id".

Below is a non-normative example of Subject Identifier for the
"saml_assertion_id" Subject Identifier Format.

~~~ json
{
    "format": "saml_assertion_id",
    "issuer": "https://idp.example.com/123456789/",
    "assertion_id": "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"
}

~~~
{: #sub-id-samlassertionid title="Example: 'saml_assertion_id' Subject
Identifier"}

### IP Addresses Subject Identifier Format {#sub-id-ips}

The "IP addresses" Subject Identifier Format specifies an array of IP addresses
observed by the Transmitter. Subject Identifiers of this format MUST contain the
following members:

ip-addresses

> REQUIRED. The array of IP addresses of the subject as observed by the
Transmitter. The value MUST be in the format of an array of strings, each one of
which represents the {{RFC4001}} string representation of an IP address.

The "IP addresses" Subject Identifier Format is identified by the name
"ip-addresses".

Below is a non-normative example of Subject Identifier for the "IP addresses"
Subject Identifier Format.

~~~ json
{
    "format": "ip-addresses",
    "ip-addresses": ["10.29.37.75", "2001:0db8:0000:0000:0000:8a2e:0370:7334"]
}

~~~
{: #sub-id-ips-example title="Example: 'ip-addresses' Subject Identifier"}

## Receiver Subject Processing {#receiver-subject-processing}

A SSF Receiver MUST make a best effort to process all members from a Subject in
an SSF event. The Transmitter Configuration Metadata ({{discovery-meta}})
defined below MAY define certain members within a Complex Subject to be
Critical. A SSF Receiver MUST discard any event that contains a Subject with a
Critical member that it is unable to process.

# Events {#events}

## Security Event Token Profile {#set-profle}

The Shared Signals Framework profiles the Security Event Token (SET)
{{RFC8417}} specification by defining certain properties of SETs as described in
this section.

### Explicit Typing of SETs {#explicit-typing}

SSF events MUST use explicit typing as defined in Section 2.3 of {{RFC8417}}.

~~~ json
{
  "typ":"secevent+jwt",
  "alg":"HS256"
}
~~~
{: title="Explicitly Typed JOSE Header" #explicit-type-header}

The purpose is defense against confusion with other JWTs, as described in
Sections 4.5, 4.6 and 4.7 of {{RFC8417}}. While current Id Token {{OpenID.Core}}
validators may not be using the "typ" header parameter, requiring it for SSF
SETs guarantees a distinct value for future validators.

### SSF Event Subject {#event-subjects}

The primary Subject Member of SSF events is described in the "Subject Members"
section ({{subject-ids}}). The JWT "sub" claim MUST NOT be present in any SET
containing an SSF event.

### Distinguishing SETs from other Kinds of JWTs

Of particular concern is the possibility that SETs are confused for other kinds
of JWTs. Section 4 of {{RFC8417}} has several sub-sections
on this subject. The Shared Signals Framework requires further restrictions:

* The "sub" claim MUST NOT be present, as described in {{event-subjects}}.
* SSF SETs MUST use explicit typing, as described in {{explicit-typing}}.
* The "exp" claim MUST NOT be present, as described in {{exp-claim}}.

### Signature Key Resolution {#signature-key-resolution}

The signature key can be obtained through "jwks_uri", see {{discovery}}.

### SSF Prescriptive SETs {#prescriptive-sets}

The Shared Signals Framework allows each deployment or integration to define its
own event processing behaviors, ranging from informational input to additional
processing needed, to mandatory enforcement.

### The "iss" Claim {#iss-claim}

The "iss" claim MUST match the "iss" value in the Stream Configuration data for
the stream that the event is sent on. Receivers MUST validate that this claim
matches the "iss" in the Stream Configuration data, as well as the Issuer from
which the Receiver requested the Transmitter Configuration data.

### The "exp" Claim {#exp-claim}

The "exp" claim MUST NOT be used in SETs.

The purpose is defense in depth against confusion with other JWTs, as described
in Sections 4.5 and 4.6 of {{RFC8417}}.

### The "aud" Claim {#aud-claim}

The "aud" claim can be a single string or an array of strings. Values that
uniquely identify the Receiver to the Transmitter MAY be used, if the two
parties have agreement on the format.

More than one value can be present if the corresponding Receivers are known to
the Transmitter to be the same entity, for example a web client and a mobile
client of the same application. All the Receivers in this case MUST use the
exact same delivery method.

If multiple Receivers have the exact same delivery configuration but the
Transmitter does not know if they belong to the same entity then the Transmitter
SHOULD issue distinct SETs for each Receiver and deliver them separately. In
this case the multiple Receivers might use the same service to process SETs, and
this service might reroute SETs to respective Receivers, an "aud" claim with
multiple Receivers would lead to unintended data disclosure.

~~~ json
{
  "jti": "123456",
  "iss": "https://transmitter.example.com",
  "aud": ["receiver.example.com/web", "receiver.example.com/mobile"],
  "iat": 1493856000,
  "txn": 8675309,
  "sub_id": {
    "format": "opaque",
    "id": "72e6991badb44e08a69672960053b342"
  },
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/verification": {
      "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="
    }
  }
}
~~~
{: title="Example: SET with array 'aud' claim" #figarrayaud}

### The "txn" claim {#txn-claim}

Transmitters SHOULD set the "txn" claim value in Security Event Tokens (SETs).
If the value is present, it MUST be unique to the underlying event that caused
the Transmitter to generate the Security Event Token (SET). The Transmitter,
however, may use the same value in the "txn" claim across different Security
Events Tokens (SETs), such as session revoked and credential change, to indicate
that the SETs originated from the same underlying cause or reason.

## Event Properties {#event-properties}

### The "events" claim {#events-claim}

The "events" claim SHOULD contain only one event. Multiple event type URIs are
permitted only if they are alternative URIs defining the exact same event type.
The type of the event is specified by the key in the value of the `events`
claim. The value of this field is the event object.

### Event type specific fields

The event object inside the `events` claim MAY have one or more fields that are
uniquely determined by the type of the event.

### Additional fields

Transmitters MAY include additional fields in SSF events. These fields MAY exist
anywhere in the SET, including the event object inside the "events" claim.
Receivers MUST ignore any fields they do not understand from the SSF events they
receive.

# Example SETs that conform to the Shared Signals Framework {#events-examples}

The following are hypothetical examples of SETs that conform to the Shared
Signals Framework.

~~~ json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "txn": 8675309,
  "aud": "636C69656E745F6964",
  "sub_id": {
    "format": "email",
    "email": "foo@example.com"
  },
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled": {}
  }
}
~~~
{: #subject-ids-ex-simple title="Example: SET Containing an SSF Event with a
Simple Subject Member"}

~~~ json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "txn": 8675309,
  "aud": "636C69656E745F6964",
  "sub_id": {
    "format": "phone_number",
    "phone_number": "+1 206 555 0123"
  },
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled": {
      "reason": "hijacking"
    }
  }
}
~~~
{: #risc-event-subject-example title="Example: SET Containing a RISC Event with
a Phone Number Subject"}

~~~ json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "txn": 8675309,
  "aud": "636C69656E745F6964",
  "sub_id": {
    "format": "email",
    "email": "user@example.com"
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
      "claims": {
        "token": "some-token-value"
      }
    }
  }
}
~~~
{: #caep-event-properties-example title="Example: SET Containing a CAEP Event
with Properties"}

~~~ json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "txn": 8675309,
  "aud": "636C69656E745F6964",
  "sub_id": {
    "format": "complex",
    "user": {
      "format": "iss_sub",
      "iss": "https://idp.example.com/3957ea72-1b66-44d6-a044-d805712b9288/",
      "sub": "jane.smith@example.com"
    },
    "device": {
      "format": "iss_sub",
      "iss": "https://idp.example.com/3957ea72-1b66-44d6-a044-d805712b9288/",
      "sub": "e9297990-14d2-42ec-a4a9-4036db86509a"
    }
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "initiating_entity": "policy",
      "reason_admin": {
        "en": "Policy Violation: C076E82F"
      },
      "reason_user": {
        "en": "Land speed violation.",
        "es": "Violación de velocidad en tierra."
      },
      "event_timestamp": 1600975810
    }
  }
}
~~~
{: #subject-ids-ex-complex title="Example: SET Containing an SSF Event with a
Complex Subject Member"}

~~~ json
{
  "iss": "https://sp.example2.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "txn": 8675309,
  "aud": "636C69656E745F6964",
  "sub_id": {
    "format": "email",
    "email": "foo@example2.com"
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
      "event_timestamp": 1600975810,
      "claims": {
         "role": "ro-admin"
      }
    }
  }
}
~~~
{: #subject-properties-ex title="Example: SET Containing an SSF Event with a
Simple Subject and a Property Member"}

~~~ json
{
  "iss": "https://myservice.example3.com/",
  "jti": "756E69717565206964656E746966696534",
  "iat": 15203800012,
  "txn": 8675309,
  "aud": "636C69656E745F6324",
  "sub_id": {
    "format": "catalog_item",
    "catalog_id": "c0384/winter/2354122"
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
      "event_timestamp": 1600975810,
      "claims": {
         "role": "ro-admin"
      }
    }
  }
}
~~~
{: #subject-custom-type-ex title="Example: SET Containing an SSF Event with a
Proprietary Subject Identifier Format"}

# Event Delivery {#event-delivery}

This section describes the supported methods of delivering SSF Events. It
provides SSF profiling specifications for the {{RFC8935}} and {{RFC8936}} specs.

## Stream Configuration Metadata {#delivery-meta}

Each delivery method is identified by a URI, specified below by the "method"
metadata.

### Push Delivery using HTTP

This section provides SSF profiling specifications for the {{RFC8935}} spec.

method

> "urn:ietf:rfc:8935"

endpoint_url

> The URL where events are pushed through HTTP POST. This is set by the
  Receiver. If a Receiver is using multiple streams from a single Transmitter
  and needs to keep the SETs separated, it is RECOMMENDED that the URL for each
  stream be unique.

authorization_header

> If the endpoint_url requires authorization, the receiver SHOULD provide this
authorization header in the stream creation/updation. If present, the
Transmitter MUST provide this value with every HTTP request to the
`endpoint_url`.

### Poll Delivery using HTTP

This section provides SSF profiling specifications for the {{RFC8936}} spec.

method

> "urn:ietf:rfc:8936"

endpoint_url

> The URL where events can be retrieved from. This is specified by the
  Transmitter. These URLs MAY be reused across Receivers, but MUST be unique per
  stream for a given Receiver.

# Transmitter Configuration Discovery {#discovery}

This section defines a mechanism for Receivers to obtain the Transmitter
Configuration Metadata.

## Transmitter Configuration Metadata {#discovery-meta}

Transmitters have metadata describing their configuration:

spec_version

> OPTIONAL. A version identifying the implementer's draft or final specification
implemented by the Transmitter. This includes the numerical portion of the spec
version as described in the document {{NAMINGCONVENTION}}. If absent, the
Transmitter is assumed to conform to "1_0-ID1" version of the specification.
>
> The following is a non-normative example of a Transmitter that implements the
> final specification of the Shared Signals Framework 1_0.

~~~ json
   {
        "spec_version": "1_0"
   }
~~~
{: #figspecversionfinal title="Example: spec_version referring to the final 1_0
spec"}

issuer

> REQUIRED. URL using the https scheme with no query or fragment component
  that the Transmitter asserts as its Issuer Identifier. This MUST be identical
  to the iss claim value in Security Event Tokens issued from this Transmitter.

jwks_uri

> OPTIONAL. URL of the Transmitter's JSON Web Key Set {{RFC7517}} document.
  This contains the signing key(s) the Receiver uses to validate signatures from
  the Transmitter. This value MUST be specified if the Transmitter intends to
  generate signed JWTs. If present, this URL MUST use HTTP over TLS {{RFC9110}}.

delivery_methods_supported

> RECOMMENDED. List of supported delivery method URIs.

configuration_endpoint

> OPTIONAL. The URL of the Configuration Endpoint. If present, this URL MUST use
HTTP over TLS {{RFC9110}}.

status_endpoint

> OPTIONAL. The URL of the Status Endpoint. If present, this URL MUST use HTTP
over TLS {{RFC9110}}.

add_subject_endpoint

> OPTIONAL. The URL of the Add Subject Endpoint. If present, this URL MUST use
HTTP over TLS {{RFC9110}}.

remove_subject_endpoint

> OPTIONAL. The URL of the Remove Subject Endpoint. If present, this URL MUST
use HTTP over TLS {{RFC9110}}.

verification_endpoint

> OPTIONAL. The URL of the Verification Endpoint. If present, this URL MUST use
HTTP over TLS {{RFC9110}}.

critical_subject_members

> OPTIONAL. An array of member names in a Complex Subject which, if present in
  a Subject Member in an event, MUST be interpreted by a Receiver.

authorization_schemes

> OPTIONAL. An array of JSON objects that specify the supported
  authorization scheme properties defined in {{authorization-scheme}}. To enable
  seamless discovery of configurations, the service provider SHOULD, with the
  appropriate security considerations, make the authorization_schemes attribute
  publicly accessible without prior authentication.

default_subjects

> OPTIONAL. A string indicating the default behavior of newly created streams.
  If present, the value MUST be either "ALL" or "NONE". If not provided, the
  Transmitter behavior in this regard is unspecified.
>
> * "ALL" indicates that any subjects that are appropriate for the stream are
    added to the stream by default. The Receiver MAY remove subjects from the
    stream via the `remove_subject_endpoint`, causing events for those subjects
    to _not_ be transmitted. The Receiver MAY re-add any subjects removed this
    way via the `add_subject_endpoint`.
> * "NONE" indicates that no subjects are added by default. The Receiver MAY add
    subjects to the stream via the `add_subject_endpoint`, causing only events
    for those subjects to be transmitted. The Receiver MAY remove subjects added
    this way via the `remove_subject_endpoint`.

### Authorization scheme {#authorization-scheme}

SSF is an HTTP based signals sharing framework and is agnostic to the
authentication and authorization schemes used to secure stream configuration
APIs. It does not provide any SSF-specific authentication and authorization
schemes but relies on the cooperating parties' mutual security considerations.

The `authorization_schemes` key of Transmitter Configuration Metadata provides
authorization information related to the Transmitter's stream management APIs.
These authorization schemes SHOULD also be used to protect any polling endpoint
(used for Poll-Based SET delivery [RFC8936]) hosted by the Transmitter.

spec_urn

> REQUIRED. A URN that describes the specification of the protocol being used.

The Receiver will call the Transmitter APIs by providing appropriate credentials
as per the `spec_urn`.

The following is a non-normative example of the `spec_urn`

~~~ json
   {
        "spec_urn": "urn:ietf:rfc:6749"
   }
~~~
{: #figspecurn title="Example: `spec_urn` specifying the OAuth protocol for
authorization"}

In this case, the Receiver may obtain an access token using the Client
Credentials Grant (Section 4.4 of {{RFC6749}}), or any other method suitable for the Receiver
and the Transmitter.

## Obtaining Transmitter Configuration Metadata

Using the Issuer URL as documented by the Transmitter, the Transmitter
Configuration Metadata can be retrieved. Receivers SHOULD ensure that the Issuer
URL comes from a trusted source and uses the `https` scheme.

Transmitters supporting Discovery MUST make a JSON document available at the
path formed by inserting the string "/.well-known/ssf-configuration" into the
Issuer between the host component and the path component, if any. The syntax
and semantics of ".well-known" are defined in {{RFC8615}}.  "ssf-configuration"
MUST point to a JSON document compliant with this specification, and that
document MUST be returned using the "application/json" content type.

### Transmitter Configuration Request

A Transmitter Configuration Document MUST be queried using an HTTP "GET" request
at the previously specified path.

The Receiver would make the following request to the Issuer
"https://tr.example.com" to obtain its Transmitter Configuration Metadata, since
the Issuer contains no path component:

~~~ http
GET /.well-known/ssf-configuration HTTP/1.1
Host: tr.example.com
~~~
{: #figdiscoveryrequest title="Example: Transmitter Configuration Request
(without path)"}

If the  Issuer value contains a path component, any terminating "/" MUST be
removed before inserting "/.well-known/ssf-configuration" between the host
component and the path component. The Receiver would make the following request
to the Issuer "https://tr.example.com/issuer1" to obtain its Transmitter
Configuration Metadata, since the Issuer contains a path component:

~~~ http
GET /.well-known/ssf-configuration/issuer1 HTTP/1.1
Host: tr.example.com
~~~
{: #figdiscoveryrequestpath title="Example: Transmitter Configuration Request
(with path)"}

Using path components enables supporting multiple issuers per host. This is
required in some multi-tenant hosting configurations. This use of ".well-known"
is for supporting multiple issuers per host; unlike its use in {{RFC8615}}, it
does not provide general information about the host.

### Backward Compatibility for RISC Transmitters

Existing RISC Transmitters MAY continue to use the path component
"/risc-configuration" instead of the path component "/ssf-configuration" in the
path for the Transmitter Configuration Metadata. New services supporting the
Shared Signals Framework SHOULD NOT use this location for publishing the
Transmitter Configuration Metadata. For example, the Transmitter Configuration
Metadata for the Transmitter "https://risc-tr.example.com" MAY be obtained by
making the following request:

~~~ http
GET /.well-known/risc-configuration HTTP/1.1
Host: risc-tr.example.com
~~~
{: #figolddiscoveryrequest title="Example: Transmitter Configuration Request for
RISC Transmitters"}

### Transmitter Configuration Response

The response is a set of Claims about the Transmitter's configuration, including
all necessary endpoints and public key location information. A successful
response MUST use the 200 OK HTTP status code and return a JSON object using the
"application/json" content type that contains a set of Claims as its members
that are a subset of the Metadata values defined in {{discovery-meta}}. Other
Claims MAY also be returned.

Claims that return multiple values are represented as JSON arrays. Claims with
zero elements MUST be omitted from the response.

An error response uses the applicable HTTP status code value.

The following is a non-normative example of a Transmitter Configuration Response

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "spec_version": "1_0",
  "issuer":
    "https://tr.example.com",
  "jwks_uri":
    "https://tr.example.com/jwks.json",
  "delivery_methods_supported": [
    "urn:ietf:rfc:8935",
    "urn:ietf:rfc:8936"],
  "configuration_endpoint":
    "https://tr.example.com/ssf/mgmt/stream",
  "status_endpoint":
    "https://tr.example.com/ssf/mgmt/status",
  "add_subject_endpoint":
    "https://tr.example.com/ssf/mgmt/subject:add",
  "remove_subject_endpoint":
    "https://tr.example.com/ssf/mgmt/subject:remove",
  "verification_endpoint":
    "https://tr.example.com/ssf/mgmt/verification",
  "critical_subject_members": [ "tenant", "user" ],
  "authorization_schemes":[
      {
        "spec_urn": "urn:ietf:rfc:6749"
      },
      {
        "spec_urn": "urn:ietf:rfc:8705"
      }
    ],
  "default_subjects": "NONE"
}
~~~
{: #figdiscoveryresponse title="Example: Transmitter Configuration Response"}

### Transmitter Configuration Validation

If any of the validation procedures defined in this specification fail, any
operations requiring the information that failed to correctly validate MUST be
aborted and the information that failed to validate MUST NOT be used.

The "issuer" value returned MUST be identical to the Issuer URL that was
directly used to retrieve the configuration information. This MUST also be
identical to the "iss" Claim value in Security Event Tokens issued from this
Transmitter.

# Management API for SET Event Streams {#management}

An Event Stream is an abstraction for how events are communicated from a
Transmitter to a Receiver. The Event Stream's configuration, which is jointly
managed by the Transmitter and Receiver, holds information about
what types of events will be sent from the Transmitter, as well as the mechanism
by which the Receiver can expect to receive the events. The Event Stream also
keeps track of what Subjects are of interest to the Receiver, and only events
with those Subjects are transmitted on the stream.

This section defines an HTTP API to be implemented by Event Transmitters
which can be used by Event Receivers to create and delete one or more Event
Streams. The API can also be used to query and update the Event Stream's
configuration and status, add and remove Subjects, and trigger verification for
those streams.

Unless there exists some other method of establishing trust between a
Transmitter and Receiver, all Stream Management API endpoints MUST use standard
HTTP authentication and authorization schemes, as per {{RFC9110}}. This
authorization MUST associate a Receiver with one or more stream IDs and "aud"
values, such that only authorized Receivers are able to access or modify the
details of the associated Event Streams.

~~~ascii
+------------+                +------------+
|            | Stream Config  |            |
| Event      <----------------+ Event      |
| Stream     |                | Receiver   |
| Management | Stream Status  |            |
| API        <----------------+            |
|            |                |            |
|            | Add Subject    |            |
|            <----------------+            |
|            |                |            |
|            | Remove Subject |            |
|            <----------------+            |
|            |                |            |
|            | Stream Updated |            |
|            +---------------->            |
|            |                |            |
|            | Verification   |            |
|            <----------------+            |
|            |                |            |
+------------+                +------------+
~~~
{: #figintro title="Event Stream Management API"}

It is OPTIONAL for Transmitters to implement a Management API, but it is
RECOMMENDED that they implement it, especially the endpoints for querying the
Stream Status and for triggering Verification.

## Event Stream Management {#management-api}

Event Receivers manage how they receive events and the subjects about which
they want to receive events over an Event Stream by making HTTP requests to
endpoints in the Event Stream Management API.

A Transmitter and Receiver MAY use the same Event Stream for updates about
multiple Subject Principals. The status of the Event Stream MAY be queried
and managed independently for each Subject Principal by Transmitters and
Receivers.

The Event Stream Management API is implemented by the Event Transmitter and
consists of the following endpoints:

Configuration Endpoint

> An endpoint used to create and delete Event Streams, as well as read and
  update an Event Stream’s current configuration.

Status Endpoint

> An endpoint used to read and update an Event Stream’s current status.

Add Subject Endpoint

> An endpoint used to add subjects to an Event Stream.

Remove Subject Endpoint

> An endpoint used to remove subjects from an Event Stream.

Verification Endpoint

> An endpoint used to request the Event Transmitter to transmit a Verification
  Event over an Event Stream.

An Event Transmitter MAY use the same URLs as endpoints for multiple Event
Receivers, provided that the Event Transmitter has some mechanism through which
they can identify the applicable set of Event Streams for any given request,
e.g. from authentication credentials. The definition of such mechanisms is
outside the scope of this specification.

### Stream Configuration {#stream-config}

An Event Stream’s configuration is a collection of data, provided by both the
Transmitter and the Receiver, that describes the information being sent over
the Event Stream. It is represented as a JSON {{RFC7159}} object with the
following properties:

stream_id

> **Transmitter-Supplied**, REQUIRED. A string that uniquely identifies the
  stream. A Transmitter MUST generate a unique ID for each of its non-deleted
  streams at the time of stream creation. Transmitters SHOULD use character set
  described in Section 2.3 of {{RFC3986}} to generate the stream ID.

iss

> **Transmitter-Supplied**, REQUIRED. A URL using the https scheme with no query
  or fragment component that the Transmitter asserts as its Issuer Identifier.
  This MUST be identical to the "iss" Claim value in Security Event Tokens
  issued from this Transmitter.

aud

> **Transmitter-Supplied**, REQUIRED. A string or an array of strings containing
  an audience claim as defined in JSON Web Token (JWT){{RFC7519}} that
  identifies the Event Receiver(s) for the Event Stream. This property cannot be
  updated. If multiple Receivers are specified then the Transmitter SHOULD know
  that these Receivers are the same entity.

events_supported

> **Transmitter-Supplied**, OPTIONAL. An array of URIs identifying the set of
  events supported by the Transmitter for this Receiver. If omitted, Event
  Transmitters SHOULD make this set available to the Event Receiver via some
  other means (e.g. publishing it in online documentation).

events_requested

> **Receiver-Supplied**, OPTIONAL. An array of URIs identifying the set of
  events that the Receiver requested. A Receiver SHOULD request only the events
  that it understands and it can act on. This is configurable by the Receiver. A
  Transmitter MUST ignore any array values that it does not understand. This
  array SHOULD NOT be empty.

events_delivered

> **Transmitter-Supplied**, REQUIRED. An array of URIs identifying the set of
  events that the Transmitter MUST include in the stream. This is a subset (not
  necessarily a proper subset) of the intersection of "events_supported" and
  "events_requested". A Receiver MUST rely on the values received in this field
  to understand which event types it can expect from the Transmitter.

delivery

> REQUIRED. A JSON object containing a set of name/value pairs specifying
  configuration parameters for the SET delivery method. The actual delivery
  method is identified by the special key "method" with the value being a URI as
  defined in {{delivery-meta}}.

min_verification_interval

> **Transmitter-Supplied**, OPTIONAL. An integer indicating the minimum amount
  of time in seconds that must pass in between verification requests. If an
  Event Receiver submits verification requests more frequently than this, the
  Event Transmitter MAY respond with a 429 status code. An Event Transmitter
  SHOULD NOT respond with a 429 status code if an Event Receiver is not
  exceeding this frequency.

description

> **Receiver-Supplied**, OPTIONAL. A string that describes the properties of the
  stream. This is useful in multi-stream systems to identify the stream for
  human actors. The transmitter MAY truncate the string beyond an allowed max
  length.

inactivity_timeout

> **Transmitter-Supplied**, OPTIONAL. The refreshable inactivity timeout of the
stream in seconds. After the timeout duration passes with no eligible activity
from the Receiver, as defined below, the Transmitter MAY either pause, disable,
or delete the stream. The syntax is the same as that of `expires_in` from
Section A.14 of {{RFC6749}}.
>
> The following constitutes eligible Receiver activity. If the Transmitter
observes any of these activities from the Receiver, it MUST restart the
inactivity timeout counter.
>
> > For streams created with the PUSH {{RFC8935}} delivery method:
> >
> > * The Receiver calls any endpoint in the Event Stream Management API that
references the stream ({{management}}).
> >
> > For streams created with the POLL {{RFC8936}} delivery method:
> >
> > * The Receiver polls the Transmitter for events in the stream.
> > * The Receiver calls any endpoint in the Event Stream Management API that
references the stream ({{management}}).
>
> If the Transmitter decides to pause or disable the stream, it MUST send a
Stream Updated Event to the Receiver as described in {{status}}.

#### Creating a Stream {#creating-a-stream}

In order to communicate events from a Transmitter to a Receiver, a Receiver
MUST first create an Event Stream. An Event Receiver creates a stream by making
an HTTP POST request to the Configuration Endpoint. On receiving a valid request
the Event Transmitter responds with a "201 Created" response containing a
JSON {{RFC7159}} representation of the stream’s configuration in the body. The
Receiver MUST check the response and confirm that the `iss` value matches the
Issuer from which it received the Transmitter Configuration data.

If a stream already exists, and the Transmitter allows multiple streams with the
same Receiver, the Event Transmitter MUST respond with a new stream ID. If the
Transmitter does not allow multiple streams with the same Receiver, it MUST
respond with HTTP status code "409 Conflict". The Receiver MAY then GET the
existing stream configuration and, if desired, use PATCH or PUT to update or
replace the existing stream configuration.

The HTTP POST request MAY contain the Receiver-Supplied values of the Stream
Configuration ({{stream-config}}) object:

* `events_requested`
* `delivery`
* `description`

If the request does not contain the `delivery` property, then the Transmitter
MUST assume that the `method` is "urn:ietf:rfc:8936" (poll). If the Transmitter
supports Poll-Based Delivery, the Transmitter MUST include a `delivery` property
in the response with this `method` property and an `endpoint_url` property. If
the Transmitter does not support the delivery method, it MAY respond with HTTP
Status Code "400 Bad Request."

Note that in the case of the poll method, the `endpoint_url` value is supplied
by the Transmitter.

The following is a non-normative example request to create an Event Stream:

~~~ http
POST /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "delivery": {
    "method": "urn:ietf:rfc:8935",
    "endpoint_url": "https://receiver.example.com/events"
  },
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
  "description" : "Stream for Receiver A using events type_2, type_3, type_4"
}
~~~
{: #figcreatestreamreq title="Example: Create Event Stream Request"}

The following is a non-normative example response:

~~~ http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "iss": "https://tr.example.com",
  "aud": [
      "https://receiver.example.com/web",
      "https://receiver.example.com/mobile"
    ],
  "delivery": {
    "method": "urn:ietf:rfc:8935",
    "endpoint_url": "https://receiver.example.com/events"
  },
  "events_supported": [
    "urn:example:secevent:events:type_1",
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3"
  ],
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
  "events_delivered": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3"
  ],
  "description" : "Stream for Receiver A using events type_2, type_3, type_4"
}
~~~
{: #figcreatestreamresp title="Example: Create Stream Response"}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 400  | if the request cannot be parsed |
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to create a stream |
| 409  | if the Transmitter does not support multiple streams per Receiver |
{: title="Create Stream Errors" #tablecreatestream}

##### Validating a Stream Creation Response

* `aud`: the Receiver SHOULD validate the `aud` in the Create Stream Response.
A Transmitter and Receiver MAY agree upon the audience value out of band.
Regardless of how the audience value is agreed upon, the Receiver SHOULD ensure
that it matches what it expects.

#### Reading a Stream’s Configuration {#reading-a-streams-configuration}

An Event Receiver gets the current configuration of a stream by making an HTTP
GET request to the Configuration Endpoint. On receiving a valid request, the
Event Transmitter responds with a "200 OK" response containing a JSON
{{RFC7159}} representation of the stream’s configuration in the body. The
Receiver MUST check the response and confirm that the `iss` value matches the
Issuer from which it received the Transmitter Configuration data.

The GET request MAY include the "stream_id" as a query parameter in order to
identify the correct Event Stream. If the "stream_id" parameter is missing,
then the Transmitter MUST return a list of the stream configurations available
to this Receiver. In the event that there are no Event Streams configured, the
Transmitter MUST return an empty list.

The following is a non-normative example request to read an Event Stream’s
configuration:

~~~ http
GET /ssf/stream?stream_id=f67e39a0a4d34d56b3aa1bc4cff0069f HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
~~~
{: title="Example: Read Stream Configuration Request" #figreadconfigreq}

The following is a non-normative example response:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "iss": "https://tr.example.com",
  "aud": [
      "https://receiver.example.com/web",
      "https://receiver.example.com/mobile"
    ],
  "delivery": {
    "method": "urn:ietf:rfc:8935",
    "endpoint_url": "https://receiver.example.com/events"
  },
  "events_supported": [
    "urn:example:secevent:events:type_1",
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3"
  ],
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
  "events_delivered": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3"
  ],
  "description" : "Stream for Receiver A using events type_2, type_3, type_4"
}
~~~
{: title="Example: Read Stream Configuration Response" #figreadconfigresp}

The following is a non-normative example request to read an Event Stream’s
configuration, with no "stream_id" indicated:

~~~ http
GET /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
~~~
{: title="Example: Read Stream Configuration
Request" #figreadconfigreqnostreamid}

The following is a non-normative example response to a request with no
"stream_id":

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

[
  {
    "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
    "iss": "https://tr.example.com",
    "aud": [
        "https://receiver.example.com/web",
        "https://receiver.example.com/mobile"
      ],
    "delivery": {
      "method": "urn:ietf:rfc:8935",
      "endpoint_url": "https://receiver.example.com/events"
    },
    "events_supported": [
      "urn:example:secevent:events:type_1",
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3"
    ],
    "events_requested": [
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3",
      "urn:example:secevent:events:type_4"
    ],
    "events_delivered": [
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3"
    ]
  },
  {
    "stream_id": "50b2d39934264897902c0581ba7c21a3",
    "iss": "https://tr.example.com",
    "aud": [
        "https://receiver.example.com/web",
        "https://receiver.example.com/mobile"
      ],
    "delivery": {
      "method": "urn:ietf:rfc:8935",
      "endpoint_url": "https://receiver.example.com/events"
    },
    "events_supported": [
      "urn:example:secevent:events:type_1",
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3"
    ],
    "events_requested": [
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3",
      "urn:example:secevent:events:type_4"
    ],
    "events_delivered": [
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3"
    ],
    "description" : "Stream for Receiver A using events type_2, type_3, type_4"
  }
]
~~~
{: title="Example: Read Stream Configuration
 Response" #figreadconfigrespnostreamidmanystreams}

The following is a non-normative example response to a request with no
"stream_id" when there is only one Event Stream configured:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

[
  {
    "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
    "iss": "https://tr.example.com",
    "aud": [
        "https://receiver.example.com/web",
        "https://receiver.example.com/mobile"
      ],
    "delivery": {
      "method": "urn:ietf:rfc:8935",
      "endpoint_url": "https://receiver.example.com/events"
    },
    "events_supported": [
      "urn:example:secevent:events:type_1",
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3"
    ],
    "events_requested": [
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3",
      "urn:example:secevent:events:type_4"
    ],
    "events_delivered": [
      "urn:example:secevent:events:type_2",
      "urn:example:secevent:events:type_3"
    ]
  }
]
~~~
{: title="Example: Read Stream Configuration
 Response" #figreadconfigrespnostreamidonestream}

The following is a non-normative example response to a request with no
"stream_id" when there are no Event Streams configured:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

[]
~~~
{: title="Example: Read Stream Configuration
 Response" #figreadconfigrespnostreamidnostreams}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to read the stream configuration |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
{: title="Read Stream Configuration Errors" #tabreadconfig}

#### Updating a Stream’s Configuration {#updating-a-streams-configuration}

An Event Receiver updates the current configuration of a stream by making an
HTTP PATCH request to the Configuration Endpoint. The PATCH body contains a
JSON {{RFC7159}} representation of the stream configuration properties to
change. On receiving a valid request, the Event Transmitter responds with a
"200 OK" response containing a JSON {{RFC7159}} representation of the entire
updated stream configuration in the body. The Receiver MUST check the response
and confirm that the `iss` value matches the Issuer from which it received the
Transmitter Configuration data.

The stream_id property MUST be present in the request. Other properties
MAY be present in the request. Any Receiver-Supplied property present in the
request MUST be updated by the Transmitter. Any properties missing in the
request MUST NOT be changed by the Transmitter. If `events_requested` property
is included in the request, it SHOULD NOT be an empty array.

Transmitter-Supplied properties besides the stream_id MAY be present,
but they MUST match the expected value. Missing Transmitter-Supplied
properties MUST be ignored by the Transmitter. The `events_delivered` property,
if present, MUST match the Transmitter's expected value before any updates are
applied.

The following is a non-normative example request to replace an Event Stream’s
configuration:

~~~ http
PATCH /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
  "description" : "Stream for Receiver B using events type_2, type_3, type_4"
}
~~~
{: title="Example: Update Stream Configuration Request" #figupdateconfigreq}

The following is a non-normative example response:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "iss": "https://tr.example.com",
  "aud": [
    "https://receiver.example.com/web",
    "https://receiver.example.com/mobile"
  ],
  "delivery": {
    "method": "urn:ietf:rfc:8935",
    "endpoint_url": "https://receiver.example.com/events"
  },
  "events_supported": [
    "urn:example:secevent:events:type_1",
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3"
  ],
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
  "events_delivered": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3"
  ],
  "description" : "Stream for Receiver B using events type_2, type_3, type_4"
}
~~~
{: title="Example: Update Stream Configuration Response" #figupdateconfigresp}

Pending conditions or errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 202  | if the update request has been accepted, but not processed. Receiver MAY try the same request later to get processing result. |
| 400  | if the request body cannot be parsed, a Transmitter-Supplied property is incorrect, or if the request is otherwise invalid |
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to update the stream configuration |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
{: title="Update Stream Configuration Errors" #tabupdateconfig}

#### Replacing a Stream’s Configuration {#replacing-a-streams-configuration}

An Event Receiver replaces the current configuration of a stream by making an
HTTP PUT request to the Configuration Endpoint. The PUT body contains a JSON
{{RFC7159}} representation of the new configuration. On receiving a valid
request, the Event Transmitter responds with a "200 OK" response containing a
JSON {{RFC7159}} representation of the updated stream configuration in the body.
The Receiver MUST check the response and confirm that the `iss` value matches
the Issuer from which it received the Transmitter Configuration data.

The stream_id and the full set of Receiver-Supplied properties MUST be present
in the PUT body, not only those specifically intended to be changed.
Missing Receiver-Supplied properties MUST be interpreted as requested to be
deleted. Event Receivers MAY read the configuration first, modify the JSON
{{RFC7159}} representation, then make a replacement request. If
`events_requested` property is included in the request, it SHOULD NOT be an
empty array.

Transmitter-Supplied properties besides the stream_id MAY be present,
but they MUST match the expected value. Missing Transmitter-Supplied
properties MUST be ignored by the Transmitter. The `events_delivered` property,
if present, MUST match the Transmitter's expected value _before_ any updates are
applied.

The following is a non-normative example request to replace an Event Stream’s
configuration:

~~~ http
PUT /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "delivery": {
    "method": "urn:ietf:rfc:8935",
    "endpoint_url": "https://receiver.example.com/events"
  },
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
  "description" : "Stream for Receiver C"
}
~~~
{: title="Example: Replace Stream Configuration Request" #figreplaceconfigreq}

The following is a non-normative example response:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "iss": "https://tr.example.com",
  "aud": [
    "https://receiver.example.com/web",
    "https://receiver.example.com/mobile"
  ],
  "delivery": {
    "method": "urn:ietf:rfc:8935",
    "endpoint_url": "https://receiver.example.com/events"
  },
  "events_supported": [
    "urn:example:secevent:events:type_1",
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3"
  ],
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
  "events_delivered": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3"
  ],
  "description" : "Stream for Receiver C"
}
~~~
{: title="Example: Replace Stream Configuration Response" #figreplaceconfigresp}

Pending conditions or errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 202  | if the replace request has been accepted, but not processed. Receiver MAY try the same request later in order to get processing result. |
| 400  | if the request body cannot be parsed, a Transmitter-Supplied property is incorrect, or if the request is otherwise invalid |
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to replace the stream configuration |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
{: title="Replace Stream Configuration Errors" #tabreplaceconfig}

#### Deleting a Stream {#deleting-a-stream}

An Event Receiver deletes a stream by making an HTTP DELETE request to the
Configuration Endpoint. On receiving a request, the Event Transmitter responds
with an empty "204 No Content" response if the configuration was successfully
removed.

The DELETE request MUST include the "stream_id" as a query parameter in order to
identify the correct Event Stream.

The following is a non-normative example request to delete an Event Stream:

~~~ http
DELETE /ssf/stream?stream_id=f67e39a0a4d34d56b3aa1bc4cff0069f HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
~~~
{: title="Example: Delete Stream Request" #figdeletestreamreq}

The following is a non-normative example response of a successful request:

~~~ http
HTTP/1.1 204 No Content
Cache-Control: no-store
~~~
{: title="Example: Delete Stream Response" #figdeletestreamresp}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to delete the stream |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
{: title="Delete Stream Errors" #tabdeletestream"}

### Stream Status {#status}

Event Streams are managed independently. A Receiver MAY request that events from
a stream be interrupted by Updating the Stream Status
({{updating-a-streams-status}}). If a Transmitter decides to enable, pause or
disable updates from a stream independently of an update request from a
Receiver, it MUST send a Stream Updated Event ({{stream-updated-event}}) to the
Receiver.

#### Reading a Stream’s Status {#reading-a-streams-status}

An Event Receiver checks the current status of an Event Stream by making an HTTP
GET request to the stream’s Status Endpoint.

The Stream Status method takes the following parameters:

stream_id

> REQUIRED. A string identifying the stream whose status is being queried.

On receiving a valid request, the Event Transmitter responds with a 200 OK
response containing a JSON {{RFC7159}} object with the following attributes:

stream_id

> REQUIRED. A string identifying the stream whose status is being queried.

status

> REQUIRED. A string whose value MUST be one of the values described below.

reason

> An OPTIONAL string whose value SHOULD express why the stream's status is set
to the current value.

The allowable "status" values are:

enabled

> The Transmitter MUST transmit events over the stream, according to the
  stream’s configured delivery method.

paused

> The Transmitter MUST NOT transmit events over the stream. The Transmitter
  SHOULD hold any events it would have transmitted while paused, and SHOULD
  transmit them when the stream’s status becomes "enabled". The Transmitter
  MAY drop zero or more events that are held when the stream is paused. If
  a Transmitter holds successive events that affect the same Subject Principal,
  then the Transmitter MUST make sure that those events are transmitted in the
  order of time that they were generated OR the Transmitter MUST send only the
  last events that do not require the previous events affecting the same Subject
  Principal to be processed by the Receiver, because the previous events are
  either cancelled by the later events or the previous events are outdated.

disabled

> The Transmitter MUST NOT transmit events over the stream and will not hold
  any events for later transmission.

The following is a non-normative example request to check an Event Stream’s
status:

~~~ http
GET /ssf/status?stream_id=f67e39a0a4d34d56b3aa1bc4cff0069f HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer zzzz
~~~
{: title="Example: Check Stream Status Request" #figstatusreq}

The following is a non-normative example response:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "status": "paused",
  "reason": "SYSTEM_DOWN_FOR_MAINTENANCE"
}
~~~
{: title="Example: Check Stream Status Response" #figstatusresp}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to read the stream status |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
{: title="Read Stream Status Errors" #tabreadstatus}

Examples:

1. If a Receiver makes an unauthorized request, then the
   Transmitter MUST respond with a 401 error status.
2. If a Receiver makes an authorized request, but the Transmitter policy
   does not permit the Receiver from obtaining the status, then the Transmitter
   MAY respond with a 403 error status.
3. If the Receiver requests the status for a stream that does not exist then the
   Transmitter MUST respond with a 404 error status.

#### Updating a Stream's Status {#updating-a-streams-status}

An Event Receiver updates the current status of a stream by making an HTTP POST
request to the Status Endpoint. The POST body contains a JSON {{RFC7159}} object
with the following fields:

stream_id

> REQUIRED. A string identifying the stream whose status is being updated.

status

> REQUIRED. The new status of the Event Stream.

reason

> OPTIONAL. A short text description that explains the reason for the change.

On receiving a valid request, the Event Transmitter responds with a "200 OK"
response containing a JSON {{RFC7159}} representation of the updated stream
status in the body, using the same fields as described in the request.

The following is a non-normative example request to update an Event Stream’s
status:

~~~ http
POST /ssf/status HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "status": "paused"
}
~~~
{: title="Example: Update Stream Status Request Without Optional
 Fields" #figupdatestatusreq}

The following is a non-normative example of an Update Stream Status request with
an optional reason:

~~~ http
POST /ssf/status HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "status": "paused",
  "reason": "Disabled by administrator action."
}
~~~
{: title="Example: Update Stream Status Request With Optional
Reason" #figupdatestatuswithreasonreq}

The following is a non-normative example response:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "status": "paused",
  "reason": "Disabled by administrator action."
}
~~~
{: title="Example: Update Stream Status Response" #figupdatestatusresp}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 202  | if the update request has been accepted, but not processed. Receiver MAY try the same request later in order to get processing result. |
| 400  | if the request body cannot be parsed or if the request is otherwise invalid |
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to update the stream status |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
{: title="Update Stream Status Errors" #tabupdatestatus}

Examples:

1. If a Receiver makes a request to update a stream status, and the Transmitter
   is unable to decide whether or not to complete the request, then the
   Transmitter MUST respond with a 202 status code.

### Subjects {#subjects}

An Event Receiver can indicate to an Event Transmitter whether or not the
Receiver wants to receive events about a particular subject by “adding” or
“removing” that subject to the Event Stream, respectively.

#### Subject Matching {#subject-matching}

If a Receiver adds a subject to a stream defined in
{{adding-a-subject-to-a-stream}}, the Transmitter SHOULD send any events
relating to the subject which have event_types that the Receiver has subscribed
to, as long as the stream status is enabled. In the case of Simple Subjects, two
subjects match if they are exactly identical. For Complex Subjects, two subjects
match if, for all fields in the Complex Subject (i.e. `user`, `group`, `device`,
etc.), at least one of the following statements is true:

1. Subject 1's field is not defined

2. Subject 2's field is not defined

3. Subject 1's field is identical to Subject 2's field

The following is a non-normative example of subject matching for Complex
Subjects when a Receiver adds a subject that is less restrictive than the
subject being sent by the Transmitter.

The Receiver has added the following subject to their stream:

~~~json
{
  "format": "complex",
  "tenant": {
    "format": "opaque",
    "id": "example-a38h4792-uw2"
  }
}
~~~

The Transmitter has an event to broadcast with the following subject:

~~~json
{
  "format": "complex",
  "tenant": {
    "format": "opaque",
    "id": "example-a38h4792-uw2"
  },
  "user": {
    "format": "email",
    "email": "jdoe@example.com"
  }
}
~~~

According to the matching rules described above, the Transmitter SHOULD
broadcast the event over the Receiver's stream.

The following is a non-normative example of subject matching for Complex
Subjects when a Receiver adds a subject that is more restrictive than the
subject being sent by the Transmitter.

The Receiver has added the following subject to their stream:

~~~json
{
  "format": "complex",
  "user": {
    "format": "email",
    "email": "jdoe@example.com"
  },
  "device": {
    "format": "ip-addresses",
    "ip-addresses": ["10.29.37.75"]
  }
}
~~~

The Transmitter has an event to broadcast with the following subject:

~~~json
{
  "format": "complex",
  "user": {
    "format": "email",
    "email": "jdoe@example.com"
  }
}
~~~

According to the matching rules described above, the Transmitter SHOULD
broadcast the event over the Receiver's stream.

The following is a non-normative example of two Complex Subjects that do not
match.

The Receiver has added the following subject to their stream:

~~~json
{
  "format": "complex",
  "user": {
    "format": "email",
    "email": "jdoe@example.com"
  },
  "group": {
    "format": "did",
    "url": "did:example:123456"
  }
}
~~~

The Transmitter has an event to broadcast with the following subject:

~~~json
{
  "format": "complex",
  "user": {
    "format": "email",
    "email": "jdoe@example.com"
  },
  "group": {
    "format": "did",
    "url": "did:example:9999999"
  }
}
~~~

According to the matching rules described above, the Transmitter SHOULD NOT
broadcast the event over the Receiver's stream.

#### Adding a Subject to a Stream {#adding-a-subject-to-a-stream}

To add a subject to an Event Stream, the Event Receiver makes an HTTP POST
request to the Add Subject Endpoint, containing in the body a JSON object the
following claims:

stream_id

> REQUIRED. A string identifying the stream to which the subject is being added.

subject

> REQUIRED. A Subject claim identifying the subject to be added.

verified

> OPTIONAL. A boolean value; when true, it indicates that the Event Receiver
  has verified the Subject claim. When false, it indicates that the Event
  Receiver has not verified the Subject claim. If omitted, Event Transmitters
  SHOULD assume that the subject has been verified.

On a successful response, the Event Transmitter responds with an empty "200 OK"
response. The Event Transmitter MAY choose to silently ignore the request, for
example if the subject has previously indicated to the Transmitter that they do
not want events to be transmitted to the Event Receiver. In this case, the
Transmitter MAY return an empty "200 OK" response or an appropriate error code.
See Security Considerations ({{management-sec}}).

The following is a non-normative example request to add a subject to a stream,
where the subject is identified by an Email Subject Identifier.

~~~ http
POST /ssf/subjects:add HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "subject": {
    "format": "email",
    "email": "example.user@example.com"
  },
  "verified": true
}
~~~
{: title="Example: Add Subject Request" #figaddreq}

The following is a non-normative example response to a successful request:

~~~ http
HTTP/1.1 200 OK
Server: transmitter.example.com
Cache-Control: no-store
~~~
{: title="Example: Add Subject Response" #figaddresp}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 400  | if the request body cannot be parsed or if the request is otherwise invalid |
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to add this particular subject, or not allowed to add in general |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver, or if the subject is not recognized by the Event Transmitter. The Event Transmitter may choose to stay silent in this second case and respond with "200" |
| 429  | if the Event Receiver is sending too many requests in a given amount of time |
{: title="Add Subject Errors" #tabadderr}

#### Removing a Subject {#removing-a-subject}

To remove a subject from an Event Stream, the Event Receiver makes an HTTP POST
request to the Remove Subject Endpoint, containing in the body a JSON object
with the following claims:

stream_id

> REQUIRED. A string identifying the stream from which the subject is being
removed.

subject

> REQUIRED. A Subject claim identifying the subject to be removed.

On a successful response, the Event Transmitter responds with a "204 No Content"
response.

The following is a non-normative example request where the subject is
identified by a Phone Number Subject Identifier:

~~~ http
POST /ssf/subjects:remove HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "subject": {
    "format": "phone",
    "phone_number": "+12065550123"
  }
}
~~~
{: title="Example: Remove Subject Request" #figremovereq}

The following is a non-normative example response to a successful request:

~~~ http
HTTP/1.1 204 No Content
Server: transmitter.example.com
Cache-Control: no-store
~~~
{: title="Example: Remove Subject Response" #figremoveresp}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 400  | if the request body cannot be parsed or if the request is otherwise invalid |
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to remove this particular subject, or not allowed to remove in general |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver, or if the subject is not recognized by the Event Transmitter. The Event Transmitter may choose to stay silent in this second case and respond with "204" |
| 429  | if the Event Receiver is sending too many requests in a given amount of time |
{: title="Remove Subject Errors" #tabremoveerr}

### Verification {#verification}

In some cases, the frequency of event transmission on an Event Stream will be
very low, making it difficult for an Event Receiver to tell the difference
between expected behavior and event transmission failure due to a misconfigured
stream. Event Receivers can request that a Verification Event be transmitted
over the Event Stream, allowing the Receiver to confirm that the stream is
configured correctly upon successful receipt of the event. The acknowledgment of
a Verification Event also confirms to the Event Transmitter that end-to-end
delivery is working, including signature verification and encryption.

A Transmitter MAY send a Verification Event at any time, even if one was
not requested by the Event Receiver.

A Transmitter MAY respond to Verification Event requests even if the event is
not present in the `events_supported`, `events_requested` and / or
`events_delivered` fields in the Stream Configuration ({{stream-config}}).

#### Verification Event {#verification-event}

The Verification Event is an SSF event with the event type:
"https://schemas.openid.net/secevent/ssf/event-type/verification". The event
contains the following attribute:

state

> OPTIONAL An opaque value provided by the Event Receiver when the event is
  triggered.

As with any SSF event, the Verification Event has a top-level `sub_id` claim:

sub_id

> REQUIRED. The value of the top-level `sub_id` claim in a Verification Event
MUST always be set to have a simple value of type `opaque`. The `id` of the
value MUST be the `stream_id` of the stream being verified.
>
> Note that the subject that identifies a stream itself is always implicitly
  added to the stream and MAY NOT be removed from the stream.

Upon receiving a Verification Event, the Event Receiver SHALL parse the SET and
validate its claims. In particular, the Event Receiver SHALL confirm that the
value for "state" is as expected. If the value of "state" does not match, an
error response with the "err" field set to "invalid_state" SHOULD be returned
(see Section 2.4 of {{RFC8935}} or Section 2.4.4 of {{RFC8936}}).

In many cases, Event Transmitters MAY disable or suspend an Event Stream that
fails to successfully verify based on the acknowledgement or lack of
acknowledgement by the Event Receiver.

#### Triggering a Verification Event. {#triggering-a-verification-event}

To request that a Verification Event be sent over an Event Stream, the Event
Receiver makes an HTTP POST request to the Verification Endpoint, with a JSON
{{RFC7159}} object containing the parameters of the verification request, if
any. On a successful request, the Event Transmitter responds with an empty
"204 No Content" response.

Verification requests have the following properties:

stream_id

> REQUIRED. A string identifying the stream that the Verification Event is being
requested on.

state

> OPTIONAL. An arbitrary string that the Event Transmitter MUST echo back to the
  Event Receiver in the Verification Event’s payload. Event Receivers MAY use
  the value of this parameter to correlate a Verification Event with a
  verification request. If the Verification Event is initiated by the
  Transmitter then this parameter MUST not be set.

A successful response from a POST to the Verification Endpoint does not indicate
that the Verification Event was transmitted successfully, only that the Event
Transmitter has transmitted the event or will do so at some point in the future.
Event Transmitters MAY transmit the event via an asynchronous process, and
SHOULD publish an SLA for Verification Event transmission times. Event Receivers
MUST NOT depend on the Verification Event being transmitted synchronously or in
any particular order relative to the current queue of events.

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 400  | if the request body cannot be parsed or if the request is otherwiseinvalid |
| 401  | if authorization failed or it is missing |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
| 429  | if the Event Receiver is sending too many requests in a given amount of time; see related "min_verification_interval" in {{stream-config}}
{: title="Verification Errors" #taberifyerr}

The following is a non-normative example request to trigger a Verification
Event:

~~~ http
POST /ssf/verify HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
Content-Type: application/json

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="
}
~~~
{: title="Example: Trigger Verification Request" #figverifyreq}

The following is a non-normative example response to a successful request:

~~~ http
HTTP/1.1 204 No Content
Server: transmitter.example.com
Cache-Control: no-store
~~~
{: title="Example: Trigger Verification Response" #figverifyresp}

And the following is a non-normative example of a Verification Event sent to the
Event Receiver as a result of the above request:

~~~ json
{
  "jti": "123456",
  "iss": "https://transmitter.example.com",
  "aud": "receiver.example.com",
  "iat": 1493856000,
  "sub_id": {
    "format": "opaque",
    "id": "f67e39a0a4d34d56b3aa1bc4cff0069f"
  },
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/verification":{
      "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="
    }
  }
}
~~~
{: title="Example: Verification SET" #figverifyset}

### Stream Updated Event {#stream-updated-event}

A Transmitter MAY change the stream status
without a request from a Receiver. The Transmitter sends an event of type
"https://schemas.openid.net/secevent/ssf/event-type/stream-updated" to indicate
that it has changed the status of the Event Stream.

If a Transmitter decides to change the status of an Event Stream from "enabled"
to either "paused" or "disabled", then the Transmitter MUST send this event to
the Receiver before stopping the stream.

If the Transmitter changes the status of the stream from either
"paused" or "disabled" to "enabled", then it MUST send this event to the
Receiver upon re-enabling the stream.

A Transmitter MAY send a Stream Updated event even if the event is not present
in the `events_supported`, `events_requested` and / or `events_delivered` fields
in the Stream Configuration ({{stream-config}}).

The "stream-updated" event contains the following claims:

status

> REQUIRED. Defines the new status of the stream.

reason

> OPTIONAL. Provides a short description of why the Transmitter has updated the
  status.

As with any SSF event, this event has a top-level `sub_id` claim:

sub_id

> REQUIRED. The top-level `sub_id` claim specifies the Stream Id for which the
status has been updated. The value of the `sub_id` field MUST be of format
`opaque`, and its `id` value MUST be the unique ID of the stream.
>
> Note that the subject that identifies a stream itself is always implicitly
  added to the stream and MAY NOT be removed from the stream.
>
> Below is a non-normative example of a Stream Updated event.

~~~ json
{
  "jti": "123456",
  "iss": "https://transmitter.example.com",
  "aud": "receiver.example.com",
  "iat": 1493856000,
  "sub_id": {
    "format": "opaque",
    "id" : "f67e39a0a4d34d56b3aa1bc4cff0069f"
  },
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/stream-updated": {
      "status": "paused",
      "reason": "Internal error"
    }
  }
}
~~~
{: title="Example: Stream Updated SET" #figstreamupdatedset}

# Security Considerations {#management-sec}

## Subject Probing {#management-sec-subject-probing}

It may be possible for an Event Transmitter to leak information about subjects
through their responses to add subject requests. A "404" response may indicate
to the Event Receiver that the subject does not exist, which may inadvertently
reveal information about the subject (e.g. that a particular individual does or
does not use the Event Transmitter service).

Event Transmitters SHOULD carefully evaluate the conditions under which they
will return error responses to add subject requests. Event Transmitters MAY
return a "204" response even if they will not actually send any events related
to the subject, and Event Receivers MUST NOT assume that a 204 response means
that they will receive events related to the subject.

## Information Harvesting {#management-sec-information-harvesting}

SETs may contain personally identifiable information (PII) or other non-public
information about the Event Transmitter, the subject (of an event in the SET),
or the relationship between the two. It is important for Event Transmitters to
understand what information they are revealing to Event Receivers when
transmitting events to them, lest the Event Stream become a vector for
unauthorized access to private information.

Event Transmitters SHOULD interpret add subject requests as statements of
interest in a subject by an Event Receiver, and ARE NOT obligated to transmit
events related to every subject an Event Receiver adds to the stream. Event
Transmitters MAY choose to transmit some, all, or no events related to any
given subject and SHOULD validate that they are permitted to share the
information contained within an event with the Event Receiver before
transmitting the event. The mechanisms by which such validation is performed
are outside the scope of this specification.

## Malicious Subject Removal {#management-sec-malicious-subject-removal}

A malicious party may find it advantageous to remove a particular subject from a
stream, in order to reduce the Event Receiver’s ability to detect malicious
activity related to the subject, inconvenience the subject, or for other
reasons. Consequently it may be in the best interests of the subject for the
Event Transmitter to continue to send events related to the subject for some
time after the subject has been removed from a stream.

Event Transmitters MAY continue sending events related to a subject for some
amount of time after that subject has been removed from the stream. Event
Receivers MUST tolerate receiving events for subjects that have been removed
from the stream, and MUST NOT report these events as errors to the Event
Transmitter.

# Privacy Considerations {#privacy-considerations}

## Subject Information Leakage {#sub-info-leakage}

Event Transmitters and Receivers SHOULD take precautions to ensure that they do
not leak information about subjects via Subject Identifiers, and choose
appropriate Subject Identifier Types accordingly. Parties SHOULD NOT identify a
subject using a given Subject Identifier Type if doing so will allow the
recipient to correlate different claims about the subject that they are not
known to already have knowledge of. Transmitters and Receivers SHOULD always use
the same Subject Identifier Type and the same claim values to identify a given
subject when communicating with a given party in order to reduce the possibility
of information leakage.

## Previously Consented Data {#previously-consented-data}

If SSF events contain new values for attributes of Subject Principals that were
previously exchanged between the Transmitter and Receiver, then there are no
additional privacy considerations introduced by providing the updated values in
the SSF events, unless the attribute was exchanged under a one-time consent
obtained from the user.

## New Data {#new-data}

Data that was not previously exchanged between the Transmitter and the Receiver,
or data whose consent to exchange has expired has the following considerations:

### Organizational Data {#organizational-data}

If a user has previously agreed with a Transmitter that they allow the release
of certain data to third-parties, then the Transmitter MAY send such data in SSF
events without additional consent of the user. Such data MAY include
organizational data about the Subject Principal that was generated by the
Transmitter.

### Consentable Data {#consentable-data}

If a Transmitter intends to include data in SSF events that is not previously
consented to be released by the user, then the Transmitter MUST obtain consent
to release such data from the user in accordance with the Transmitter's privacy
policy.

# IANA Considerations {#iana}

Subject Identifiers defined in this document will be added to the "Security
Events Subject Identifier Types" registry. This registry is defined in the
Subject Identifiers for Security Event Tokens {{RFC9493}} specification.

The `ssf-configuration` well-known endpoint is registered in IANA's Well-Known
URIs registry, as defined by {{RFC8615}}.

IANA is asked to assign the error code "invalid_state", as defined in
{{verification-event}}, to the Security Event Token Error Codes section of the
Security Event Token registry, as defined in Section 7.1 of {{RFC8935}}. The
following information is provided as required by the registration template:

Error Code

> invalid_state

Description

> Indicates that a Verification event contained a "state" claim that does not
  match the value expected by the Receiver.

Change Controller

> OpenID - Shared Signals Working Group

--- back

# Acknowledgements

The authors wish to thank all members of the OpenID Foundation SSF
Working Group who contributed to the development of this
specification.

# Notices

Copyright (c) 2025 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer,
or other interested party a non-exclusive, royalty free, worldwide copyright license to
reproduce, prepare derivative works from, distribute, perform and display, this
Implementers Draft, Final Specification, or Final Specification Incorporating Errata
Corrections solely for the purposes of (i) developing specifications, and (ii)
implementing Implementers Drafts, Final Specifications, and Final Specification
Incorporating Errata Corrections based on such documents, provided that attribution
be made to the OIDF as the source of the material, but that such attribution does not
indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions
from various sources, including members of the OpenID Foundation and others.
Although the OpenID Foundation has taken steps to help ensure that the technology
is available for distribution, it takes no position regarding the validity or scope of any
intellectual property or other rights that might be claimed to pertain to the
implementation or use of the technology described in this specification or the extent
to which any license under such rights might or might not be available; neither does it
represent that it has made any independent effort to identify any such rights. The
OpenID Foundation and the contributors to this specification make no (and hereby
expressly disclaim any) warranties (express, implied, or otherwise), including implied
warranties of merchantability, non-infringement, fitness for a particular purpose, or
title, related to this specification, and the entire risk as to implementing this
specification is assumed by the implementer. The OpenID Intellectual Property
Rights policy (found at openid.net) requires contributors to offer a patent promise not
to assert certain patent claims against other contributors and against implementers.
OpenID invites any interested party to bring to its attention any copyrights, patents,
patent applications, or other proprietary rights that may cover technology that may be
required to practice this specification.

# Document History

  [[ To be removed from the final specification ]]

-23

* Cleaned up markdown (#91)
* Added language to allow implementations to define their own processing
behavior for SETS (#255)

-20

* Clarified that Transmitters may drop events if they aren't able to deliver
them to the receiver.
* Added examples to demonstrate how "wildcard matching" works in SSF event
complex subjects
* Added an `inactivity_timeout` field to the Transmitter metadata, after which
transmitters may pause, disable or delete inactive streams.
* Clarified that Receivers should validate the `aud` value
* Clarified that Transmitters may include additional fields in SSF events, and
how receivers should interpret them.
* Specified that the poll delivery endpoint should require authorization
* Clarified stream creation behavior for delivery method mismatch and poll
delivery
* Clarified that StreamIDs have to be of the "unreserved characters" character
set from RFC3986
* Clarified the authorization_header requirement for the receiver
* Rearranged the content for easier readability: Eliminated the "Profiles"
section (previous section 10). Created new sections "Events" (new section 4),
and "Event Delivery" (new Section 6). Incorporated text from the erstwhile
"Profiles" section into other sections as appropriate. Fixed references and
titles of examples.
* Added "IP Address" as a subject identifier format
* In Create Stream, specified that description may be included in the response,
and that the `endpoint_url` is specified by the Transmitter in the `poll`
delivery method
* Updated URLs of linked specs and other resources
* Fixed example to have correct format for "reason_admin" and "reason_user"

-03

* Removing transmitter supplied fields from stream config PUT and PATCH examples
* Add OPTIONAL/REQUIRED to the fields in the stream configuration
* Add stream_id to the response when getting stream status
* Update subject/sub_id in examples. Fix CAEP example
* Clarify language around sending Stream Updated events
* Add sentence suggesting that Issuer information should be validated by the
Receiver
* Removed cause-time from RISC example
* Fix description of error code for invalid state
* Add SHOULD language about checking the issuer value
* Added language requiring authorization of stream management API
* Added description of `txn` claim
* Added a `default_subjects` field to Transmitter Configuration Metadata
indicating expected subject behavior for new streams
* added txn claims to non-normative SET examples and generic txn callout under
SET Profile section RFC8417
* Editorial: Standardize terms and casing, fix some typos

-02

* added spec version to metadata
* Added description as receiver supplied
* added language to make verification and updated events independent of
events_supported
* added top-level sub_id claim. Modified existing language to reflect the use of
the sub_id claim
* updated text to reflect sub_id as a top-level field in verification and stream
updated events
* \#46 add stream exists behavior
* update stream exists to 409
* Add 'format' to normative examples in CAEP
* Remove 'format' from stream config
* Remove subject from stream status (#88)
* Add reason to GET /status response
* Make reason look like an enum in the example to indicate how we expect it to
be used
* Fixes \#60 - are subjects required
* Added format field to complex subjects and updated examples (#71)
* Switch stray '204 OK' to read '204 No Content' (#73)
* Change 'jwt-id' to 'jwt_id' to match style of other subject formats (#63)
* resolving issue \#45 added explanatory text to Stream Configuration (#68)
* \#28 update delivery method references to URNs (#49)
* Changed jwks_uri from REQUIRED to OPTIONAL (#47)
* Sse to ssf (#43)
* updated SSE to Shared Signals in all files
* changed source format to md
* renamed files to be called sharedsignals instead of SSE. No change to the
content (#41)
* Add stream_id to SSE Framework spec as per Issue 4:
https://github.com/openid/sse/issues/4
* Update README with development instructions and fix error in Makefile
* Added note to PUSH/POLL section about uniqueness requirements for the URLs
* Add explanation about what an Event Stream is
* Change terms to Transmitter-Supplied and Receiver-Supplied
* Pragma is an obsolete HTTP header
* It's unnecessary to specify the character as UTF-8 in all examples (#10)
* Fix issue \#18 by converting saml-assertion-id to saml_assertion_id to
maintain consistent formatting with other subject identifiers (#1)
* updated backward compatibility language
* added section for Transmitter Configuration Metadata RISC compatibility
