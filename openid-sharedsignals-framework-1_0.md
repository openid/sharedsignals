---
title: OpenID Shared Signals Framework Specification 1.0 - draft 02
abbrev: SharedSignals
docname: openid-sharedsignals-framework-1_0
date: 2023-02-08

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

normative:
  CLIENTCRED:
    author:
    - ins: D. Hardt
      name: D. Hardt
    date: October 2012
    seriesinfo:
      DOI: 10.17487/RFC6749
      RFC: '6749'
    target: https://tools.ietf.org/html/rfc6749#section-4.4
    title: The OAuth 2.0 Authorization Framework - Client Credentials Grant

  DELIVERYPOLL:
    author:
    - ins: A. Backman
      name: Annabelle Backman
    - ins: M. Jones
      name: Michael B. Jones
    - ins: M.S. Scurtescu
      name: Marius Scurtescu
    - ins: M. Ansari
      name: Morteza Ansari
    - ins: A. Nadalin
      name: Anthony Nadalin
    date: November 2020
    target: https://www.rfc-editor.org/info/rfc8936
    title: Poll-Based SET Token Delivery Using HTTP
  DELIVERYPUSH:
    author:
    - ins: A. Backman
      name: Annabelle Backman
    - ins: M. Jones
      name: Michael B. Jones
    - ins: P. Hunt
      name: Phil Hunt
    - ins: M.S. Scurtescu
      name: Marius Scurtescu
    - ins: M. Ansari
      name: Morteza Ansari
    - ins: A. Nadalin
      name: Anthony Nadalin
    date: November 2020
    target: https://www.rfc-editor.org/info/rfc8935
    title: Push-Based SET Token Delivery Using HTTP
  IDTOKEN:
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
    date: April 2017
    target: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    title: OpenID Connect Core 1.0 - ID Token
  OASIS.saml-core-2.0-os:
  OAUTH-DISCOVERY:
    author:
    - ins: M.B. Jones
      name: Michael B. Jones
      org: Microsoft
    - ins: N. Sakimura
      name: Nat Sakimura
      org: Nomura Research Institute, Ltd.
    - ins: J. Bradley
      name: John Bradley
      org: Ping Identity
    date: June 2018
    target: https://www.rfc-editor.org/info/rfc8414
    title: OAuth 2.0 Authorization Server Metadata - Version 10
  OPENID-DISCOVERY:
    author:
    - ins: N. Sakimura
      name: Nat Sakimura
      org: Nomura Research Institute, Ltd.
    - ins: J. Bradley
      name: John Bradley
      org: Ping Identity
    - ins: M.B. Jones
      name: Michael B. Jones
      org: Microsoft
    - ins: E. Jay
      name: Edmund Jay
      org: Illumila
    date: November 2014
    target: https://openid.net/specs/openid-connect-discovery-1_0.html
    title: OpenID Connect Discovery 1.0
  RFC2119:
  RFC5785:
  RFC6750:
  RFC7159:
  RFC7517:
  RFC7519:
  RFC8174:
  RFC8417:
  SUBIDS:
    author:
    - ins: A. Backman
      name: Annabelle Backman
    - ins: M. Scurtescu
      name: Marius Scurtescu
    date: May 2021
    target: https://datatracker.ietf.org/doc/html/draft-ietf-secevent-subject-identifiers
    title: Subject Identifiers for Security Event Tokens

informative:
  CAEP:
    author:
    - ins: A. Tulshibagwale
      name: Atul Tulshibagwale
      org: Google
    date: February 2019
    target: https://cloud.google.com/blog/products/identity-security/re-thinking-federated-identity-with-the-continuous-access-evaluation-protocol
    title: '               Re-thinking Federated Identity with the Continuous Access Evaluation Protocol             '
  USECASES:
    author:
    - ins: M. Scurtescu
      name: Marius Scurtescu
    date: June 2017
    target: https://tools.ietf.org/html/draft-scurtescu-secevent-risc-use-cases-00
    title: Security Events RISC Use Cases

--- abstract

This Shared Signals Framework (SSF) enables sharing of signals and events
between cooperating peers. It enables multiple applications such as Risk Incident Sharing
and Coordination (RISC) and the Continuous Access Evaluation Profile ({{CAEP}})

This specification defines:

* A profile for Security Events Tokens {{RFC8417}}
* Subject Principals
* Subject Claims in SSF Events
* Event Types
* Event Properties
* Configuration information and discovery method for Transmitters
* A Management API for Event Streams

This spec also directly profiles several IETF Security Events drafts:

* Security Event Token (SET) {{RFC8417}}
* Subject Identifiers for Security Event Tokens {{SUBIDS}}
* Push-Based SET Token Delivery Using HTTP {{DELIVERYPUSH}} 
* Poll-Based SET Token Delivery Using HTTP {{DELIVERYPOLL}} 

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

Subject Principals are the managed entities in a SSF Transmitter or Receiver.
These include human or robotic principals, devices, customer tenants in a
multi-tenanted service, organizational units within a tenant, groups of subject
principals, or other entities that are managed by Transmitters and Receivers.
There may be other actors or resources that can be treated as Subject
Principals, and event-type definitions SHOULD specify the range of principals
addressed by the event.

Subject Principals are identified by Subject Members defined below.

# Subject Members in SSF Events {#subject-ids}

A member of type Subject in an SSF event MAY have any claim name. Each Subject Member MUST
refer to exactly one Subject Principal.

A Subject may be a "simple subject" or a "complex subject".

## Simple Subject Members {#simple-subjects}

A Simple Subject Member has a claim name and a value that is a "Subject
Identifier" as defined in the Subject Identifiers for Security Event Tokens
{{SUBIDS}}. Below is a non-normative example of a Simple Subject Member in a SSF
event.

~~~ json
"transferer": {
  "format": "email",
  "email": "foo@example.com"
}
~~~
{: #simple-subject-ex title="Example: Simple Subject"}

## Complex Subject Members {#complex-subjects}

A Complex Subject Member has a name and a value that is a JSON {{RFC7159}}
object that has one or more Simple Subject Members. The name of each Simple
Subject Member in this value MAY be one of the following:

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

Additional Subject Member names MAY be used in Complex Subjects. Each member name MAY
appear at most once in the Complex Subject value.

Below is a non-normative example of a Complex Subject claim in a SSF event.

~~~ json
"transferee": {
  "user" : {
    "format": "email",
    "email": "bar@example.com"
  },
  "tenant" : {
    "format": "iss_sub",
    "iss" : "http://example.com/idp1",
    "sub" : "1234"
  }
}
~~~ 
{: #complex-subject-ex title="Example: Complex Subject"}

### Complex Subject Interpretation {#complex-subject-interpretation}

All members within a Complex Subject MUST represent attributes of the same
Subject Principal. As a whole, the Complex Subject MUST refer to exactly one
Subject Principal.

## Subject Identifiers in SSF Events {#subject-ids-in-ssf}

A Subject Identifier in a SSF event MUST have an identifier format that is any
one of:

* Defined in the IANA Registry defined in Subject Identifiers for Security
Event Tokens {{SUBIDS}}
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
identifier, defined in  {{RFC7519}}. Subject Identifiers of this type MUST
contain the following members:

iss

> REQUIRED. The "iss" (issuer) claim of the JWT being identified, defined in
  {{RFC7519}}

jti

> REQUIRED. The "jti" (JWT token ID) claim of the JWT being identified, defined
  in {{RFC7519}}

The "JWT ID" Subject Identifier Format is identified by the name "jwt-id".

Below is a non-normative example of Subject Identifier for the "jwt-id" Subject
Identifier Format.

~~~ json
{
    "format": "jwt-id",
    "iss": "https://idp.example.com/123456789/",
    "jti": "B70BA622-9515-4353-A866-823539EECBC8"
}
~~~
{: #sub-id-jwtid title="Example: 'jwt-id' Subject Identifier"}

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

Below is a non-normative example Subject Identifier for the "saml_assertion_id"
Subject Identifier Format.

~~~ json
{
    "format": "saml_assertion_id",
    "issuer": "https://idp.example.com/123456789/",
    "assertion_id": "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"
}

~~~
{: #sub-id-samlassertionid title="Example: 'saml_assertion_id' Subject Identifier"}

## Receiver Subject Processing {#receiver-subject-processing}

A SSF Receiver MUST make a best effort to process all members from a Subject in
an SSF event. The Transmitter Configuration Metadata ({{discovery-meta}}) defined
below MAY define certain members within a Complex Subject to be Critical. A SSF
Receiver MUST discard any event that contains a Subject with a Critical member
that it is unable to process.

# Event Properties  {#properties}

Additional members about an event may be included in the "events" claim. Some
of these members are required and specified as such in the respective event
types specs. If a Transmitter determines that it needs to include additional
members that are not specified in the event types spec, then the name of such
members MUST be a URI. The discoverability of all additional members is 
specified in the Discovery {{discovery}} section.

# Example SETs that conform to the Shared Signals Framework {#events-examples}

The following are hypothetical examples of SETs that conform to the Shared Signals Framework.

~~~ json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "aud": "636C69656E745F6964",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled": {
      "subject": {
        "format": "email",
        "email": "foo@example.com"
      }
    }
  }
}
~~~
{: #subject-ids-ex-simple title="Example: SET Containing a SSF Event with a Simple Subject Member"}

~~~ json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "aud": "636C69656E745F6964",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "subject": {
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
      "initiating_entity": "policy",
      "reason_admin": "Policy Violation: C076E82F",
      "reason_user": "Landspeed violation.",
      "event_timestamp": 1600975810
    }
  }
}
~~~
{: #subject-ids-ex-complex title="Example: SET Containing a SSF Event with a Complex Subject Member"}

~~~ json
{
  "iss": "https://sp.example2.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "aud": "636C69656E745F6964",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
      "subject": {
        "format": "email",
        "email": "foo@example2.com"
      },
      "event_timestamp": 1600975810,
      "claims": {
         "role": "ro-admin"
      }
    }
  }
}
~~~
{: #subject-properties-ex title="Example: SET Containing a SSF Event with a Simple Subject and a Property Member"}

~~~ json
{
  "iss": "https://myservice.example3.com/",
  "jti": "756E69717565206964656E746966696534",
  "iat": 15203800012,
  "aud": "636C69656E745F6324",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change": {
    "subject": {
        "format": "catalog_item",
        "catalog_id": "c0384/winter/2354122"
      },
      "event_timestamp": 1600975810,
      "claims": {
         "role": "ro-admin"
      }
    }
  }
}
~~~
{: #subject-custom-type-ex title="Example: SET Containing a SSF Event with a Proprietary Subject Identifier Format"}

# Transmitter Configuration Discovery {#discovery}

This section defines a mechanism for Receivers to obtain Transmitter
configuration information.

## Transmitter Configuration Metadata {#discovery-meta}

Transmitters have metadata describing their configuration:

issuer

> REQUIRED. URL using the https scheme with no query or fragment component
  that the Transmitter asserts as its Issuer Identifier. This MUST be identical
  to the iss claim value in Security Event Tokens issued from this Transmitter.

jwks_uri

> REQUIRED. URL of the Transmitter's JSON Web Key Set {{RFC7517}} document.
  This contains the signing key(s) the Receiver uses to validate signatures from
  the Transmitter.

delivery_methods_supported

> RECOMMENDED. List of supported delivery method URIs.

configuration_endpoint

> OPTIONAL. The URL of the Configuration Endpoint.

status_endpoint

> OPTIONAL. The URL of the Status Endpoint.

add_subject_endpoint

> OPTIONAL. The URL of the Add Subject Endpoint.

remove_subject_endpoint

> OPTIONAL. The URL of the Remove Subject Endpoint.

verification_endpoint

> OPTIONAL. The URL of the Verification Endpoint.

critical_subject_members

> OPTIONAL. List of member names in a Complex Subject which, if present in
  a Subject Member in an event, MUST be interpreted by a Receiver.

TODO: consider adding a IANA Registry for metadata, similar to Section 7.1.1 of
{{OAUTH-DISCOVERY}}. This would allow other specs to add to the metadata.

## Obtaining Transmitter Configuration Information

Using the Issuer as documented by the Transmitter, the Transmitter Configuration
Information can be retrieved.

Transmitters supporting Discovery MUST make a JSON document available at the
path formed by inserting the string "/.well-known/ssf-configuration" into the
Issuer between the host component and the path component, if any. The syntax
and semantics of ".well-known" are defined in {{RFC5785}}.  "ssf-configuration"
MUST point to a JSON document compliant with this specification and MUST be
returned using the "application/json" content type.

### Transmitter Configuration Request

A Transmitter Configuration Document MUST be queried using an HTTP "GET" request
at the previously specified path.

The Receiver would make the following request to the Issuer
"https://tr.example.com" to obtain its Configuration information, since the
Issuer contains no path component:

~~~ http
GET /.well-known/ssf-configuration HTTP/1.1
Host: tr.example.com
~~~
{: #figdiscoveryrequest title="Example: Transmitter Configuration Request (without path)"}

If the  Issuer value contains a path component, any terminating "/" MUST be
removed before inserting "/.well-known/ssf-configuration" between the host
component and the path component. The Receiver would make the following request
to the Issuer "https://tr.example.com/issuer1" to obtain its Configuration
information, since the Issuer contains a path component:

~~~ http
GET /.well-known/ssf-configuration/issuer1 HTTP/1.1
Host: tr.example.com
~~~
{: #figdiscoveryrequestpath title="Example: Transmitter Configuration Request (with path)"}

Using path components enables supporting multiple issuers per host. This is
required in some multi-tenant hosting configurations. This use of ".well-known"
is for supporting multiple issuers per host; unlike its use in {{RFC5785}}, it
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
{: #figolddiscoveryrequest title="Example: Transmitter Configuration Request for RISC Transmitters"}

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

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "issuer":
    "https://tr.example.com",
  "jwks_uri":
    "https://tr.example.com/jwks.json",
  "delivery_methods_supported": [
    "https://schemas.openid.net/secevent/risc/delivery-method/push",
    "https://schemas.openid.net/secevent/risc/delivery-method/poll"],
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
  "critical_subject_members": [ "tenant", "user" ]
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
what types of events will be sent from the Transmitter, as well as the mechanism by
which the Receiver can expect to receive the events. The Event Stream also keeps
track of what Subjects are of interest to the Receiver, and only events with those
Subjects are transmitted on the stream.

This section defines an HTTP API to be implemented by Event Transmitters
which can be used by Event Receivers to create and delete one or more Event Streams.
The API can also be used to query and update the Event Stream's configuration and status,
add and remove Subjects, and trigger verification for those streams.

~~~
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
Event Receivers manage how they receive events, and the subjects about which
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

> An endpoint used to request the Event Transmitter transmit a Verification
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

> **Transmitter-Supplied**, A string that uniquely identifies the stream. Stream
  IDs MUST be unique per Reciever.  This value is generated by the Transmitter
  when the stream is created.

iss

> **Transmitter-Supplied**, A URL using the https scheme with no query or
  fragment component that the Transmitter asserts as its Issuer Identifier. This
  MUST be identical to the "iss" Claim value in Security Event Tokens issued
  from this Transmitter.

aud

> **Transmitter-Supplied**, A string or an array of strings containing an
  audience claim as defined in JSON Web Token (JWT){{RFC7519}} that identifies
  the Event Receiver(s) for the Event Stream. This property cannot be updated.
  If multiple Receivers are specified then the Transmitter SHOULD know that
  these Receivers are the same entity.

events_supported

> **Transmitter-Supplied**, An array of URIs identifying the set of events
  supported by the Transmitter for this Receiver. If omitted, Event Transmitters
  SHOULD make this set available to the Event Receiver via some other means
  (e.g. publishing it in online documentation).

events_requested

> **Receiver-Supplied**, An array of URIs identifying the set of events that
  the Receiver requested. A Receiver SHOULD request only the events that it
  understands and it can act on. This is configurable by the Receiver.

events_delivered

> **Transmitter-Supplied**, An array of URIs which is the intersection of
  "events_supported" and "events_requested". These events MAY be delivered over
              the Event Stream.

delivery

> **Receiver-Supplied**, A JSON object containing a set of name/value pairs
  specifying configuration parameters for the SET delivery method.  The actual
  delivery method is identified by the special key "method" with the value being
  a URI as defined in {{delivery-meta}}.

min_verification_interval

> **Transmitter-Supplied**, An integer indicating the minimum amount of time in
  seconds that must pass in between verification requests. If an Event Receiver
  submits verification requests more frequently than this, the Event Transmitter
  MAY respond with a 429 status code. An Event Transmitter SHOULD NOT respond
  with a 429 status code if an Event Receiver is not exceeding this frequency.

format

> **Receiver-Supplied**, The Subject Identifier Format that the Receiver wants
  for the events. If not set then the Transmitter might decide to use a type
  that discloses more information than necessary.

TODO: consider adding a IANA Registry for stream configuration metadata, similar
to Section 7.1.1 of {{OAUTH-DISCOVERY}}. This would allow other specs to add to
the stream configuration.


#### Creating a Stream {#creating-a-stream}
In order to communicate events from a Transmitter to a Receiver, a Receiver
MUST first create an Event Stream. An Event Receiver creates a stream by making
an HTTP POST request to the Configuration Endpoint. On receiving a valid request
the Event Transmitter responds with a "201 Created" response containing a
[JSON][RFC7159] representation of the stream’s configuration in the body.

The HTTP POST request MAY contain the Receiver-Supplied values of the Stream
Configuration ({{stream-config}}) object:

events_requested

> **Receiver-Supplied**, An array of URIs identifying the set of events that
  the Receiver requested. A Receiver SHOULD request only the events that it
  understands and it can act on. This is configurable by the Receiver.

delivery

> **Receiver-Supplied**, A JSON object containing a set of name/value pairs
  specifying configuration parameters for the SET delivery method. The actual
  delivery method is identified by the special key "method" with the value
  being a URI as defined in {{delivery-meta}}.

format

> **Receiver-Supplied**, The Subject Identifier Format that the Receiver wants
  for the events. If not set then the Transmitter might decide to use a type
  that discloses more information than necessary.

The following is a non-normative example request to create an Event Stream:

~~~ http
POST /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "delivery": {
    "delivery_method":
      "https://schemas.openid.net/secevent/risc/delivery-method/push",
      "url": "https://receiver.example.com/events"
  },
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ]
}
~~~
{: #figcreatestreamreq title="Example: Create Event Stream Request"}

The following is a non-normative example response:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "iss": "https://tr.example.com",
  "aud": [
      "http://receiver.example.com/web",
      "http://receiver.example.com/mobile"
    ],
  "delivery": {
    "delivery_method":
      "https://schemas.openid.net/secevent/risc/delivery-method/push",
    "url": "https://receiver.example.com/events"
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
~~~
{: #figcreatestreamresp title="Example: Create Stream Response"}

Errors are signaled with HTTP status codes as follows:


| Code | Description |
|------|-------------|
| 400  | if the request cannot be parsed |
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to create a stream |
{: title="Create Stream Errors" #tablecreatestream}


#### Reading a Stream’s Configuration {#reading-a-streams-configuration}
An Event Receiver gets the current configuration of a stream by making an HTTP
GET request to the Configuration Endpoint. On receiving a valid request the
Event Transmitter responds with a "200 OK" response containing a [JSON][RFC7159]
representation of the stream’s configuration in the body.

The GET request MAY include the "stream_id" as a parameter in order to
identify the correct Event Stream. If the "stream_id" argument is missing,
then the Transmitter MUST return a list of the stream configurations available
to this Receiver. In the event that there are no Event Streams created, the
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
      "http://receiver.example.com/web",
      "http://receiver.example.com/mobile"
    ],
  "delivery": {
    "delivery_method":
      "https://schemas.openid.net/secevent/risc/delivery-method/push",
    "url": "https://receiver.example.com/events"
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
~~~
{: title="Example: Read Stream Configuration Response" #figreadconfigresp}

The following is a non-normative example request to read an Event Stream’s
configuration, with no "stream_id" indicated:

~~~ http
GET /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
~~~
{: title="Example: Read Stream Configuration Request" #figreadconfigreqnostreamid}

The following is a non-normative example response to a request with no "stream_id":

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

[
  {
    "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
    "iss": "https://tr.example.com",
    "aud": [
        "http://receiver.example.com/web",
        "http://receiver.example.com/mobile"
      ],
    "delivery": {
      "delivery_method":
        "https://schemas.openid.net/secevent/risc/delivery-method/push",
      "url": "https://receiver.example.com/events"
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
        "http://receiver.example.com/web",
        "http://receiver.example.com/mobile"
      ],
    "delivery": {
      "delivery_method":
        "https://schemas.openid.net/secevent/risc/delivery-method/push",
      "url": "https://receiver.example.com/events"
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
{: title="Example: Read Stream Configuration Response" #figreadconfigrespnostreamidmanystreams}

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
        "http://receiver.example.com/web",
        "http://receiver.example.com/mobile"
      ],
    "delivery": {
      "delivery_method":
        "https://schemas.openid.net/secevent/risc/delivery-method/push",
      "url": "https://receiver.example.com/events"
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
{: title="Example: Read Stream Configuration Response" #figreadconfigrespnostreamidonestream}

The following is a non-normative example response to a request with no "stream_id"
when there are no Event Streams configured:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

[]
~~~
{: title="Example: Read Stream Configuration Response" #figreadconfigrespnostreamidnostreams}

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
[JSON][RFC7159] representation of the stream configuration properties to change. On
receiving a valid request the Event Transmitter responds with a "200 OK"
response containing a [JSON][RFC7159] representation of the entire updated stream
configuration in the body.

The stream_id property MUST be present in the request. Other properties
MAY be present in the request. Any Receiver-Supplied property present in the
request MUST be updated by the Transmitter. Any properties missing in the
request MUST NOT be changed by the Transmitter.

Transmitter-Supplied properties beside the stream_id MAY be present,
but they MUST match the expected value. Missing Transmitter-Supplied
properties will be ignored by the Transmitter.

The following is a non-normative example request to replace an Event Stream’s
configuration:

~~~ http
PATCH /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "iss": "https://tr.example.com",
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
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
    "http://receiver.example.com/web",
    "http://receiver.example.com/mobile"
  ],
  "delivery": {
    "delivery_method":
      "https://schemas.openid.net/secevent/risc/delivery-method/push",
    "url": "https://receiver.example.com/events"
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
request the Event Transmitter responds with a "200 OK" response containing a
JSON {{RFC7159}} representation of the updated stream configuration in the body.

The stream_id and the full set of Receiver-Supplied properties MUST be present
in the PUT body, not only the ones that are specifically intended to be changed.
Missing Receiver-Supplied properties MUST be interpreted as requested to be
deleted. Event Receivers MAY read the configuration first, modify the JSON
{{RFC7159}} representation, then make a replacement request.

Transmitter-Supplied properties besides the stream_id MAY be present,
but they MUST match the expected value. Missing Transmitter-Supplied
properties will be ignored by the Transmitter.

The following is a non-normative example request to replace an Event Stream’s
configuration:

~~~ http
PUT /ssf/stream HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "iss": "https://tr.example.com",
  "aud": [
    "http://receiver.example.com/web",
    "http://receiver.example.com/mobile"
  ],
  "delivery": {
    "delivery_method":
      "https://schemas.openid.net/secevent/risc/delivery-method/push",
    "url": "https://receiver.example.com/events"
  },
  "events_requested": [
    "urn:example:secevent:events:type_2",
    "urn:example:secevent:events:type_3",
    "urn:example:secevent:events:type_4"
  ],
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
    "http://receiver.example.com/web",
    "http://receiver.example.com/mobile"
  ],
  "delivery": {
    "delivery_method":
      "https://schemas.openid.net/secevent/risc/delivery-method/push",
    "url": "https://receiver.example.com/events"
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
Configuration Endpoint. On receiving a request the Event Transmitter responds
with an empty "204 OK" response if the configuration was successfully removed.

The DELETE request MUST include the "stream_id" as a parameter in order to
identify the correct Event Stream.

The following is a non-normative example request to delete an Event Stream:

~~~ http
DELETE /ssf/stream?stream_id=f67e39a0a4d34d56b3aa1bc4cff0069f HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
~~~
{: title="Example: Delete Stream Request" #figdeletestreamreq}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to delete the stream |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
{: title="Delete Stream Errors" #tabdeletestream"}

### Stream Status {#status}
Within an Event Stream, events related to different Subject Principals MAY be
managed independently. A Receiver MAY request Subject Principals to be added to
or removed from a stream by Updating the Stream Status
({{updating-a-streams-status}}) and specifying the Subject in the request.

A Transmitter MAY decide to enable, pause or disable updates about a Subject
independently of an update request from a Receiver. If a Transmitter decides to
start or stop events for a Subject then the Transmitter MUST do the following
according to the status of the stream.

If the stream is:

Enabled

> the Transmitter MUST send a stream updated ({{stream-updated-event}}) event
  respectively to the Receiver within the Event Stream.

Paused

> the Transmitter SHOULD send a stream updated ({{stream-updated-event}}) after the Event Stream is
  re-started. A Receiver MUST assume that events may have been lost during the
  time when the event stream was paused.

Disabled

> the Transmitter MAY send a stream updated ({{stream-updated-event}}) after the Event Stream is
  re-enabled.

#### Reading a Stream’s Status {#reading-a-streams-status}
An Event Receiver checks the current status of an event stream by making an HTTP
GET request to the stream’s Status Endpoint.

The Stream Status method takes the following parameters:

stream_id

> REQUIRED. The stream whose status is being queried.

subject

> OPTIONAL. The subject for which the stream status is requested.

On receiving a valid request the Event Transmitter responds with a 200 OK
response containing a [JSON][RFC7159] object with an attribute "status",
whose string value MUST have one of the following values:

enabled

> The Transmitter MUST transmit events over the stream, according to the
  stream’s configured delivery method.

paused

> The Transmitter MUST NOT transmit events over the stream. The transmitter
  will hold any events it would have transmitted while paused, and SHOULD
  transmit them when the stream’s status becomes "enabled". If a Transmitter
  holds successive events that affect the same Subject Principal, then the
  Transmitter MUST make sure that those events are transmitted in the order of
  time that they were generated OR the Transmitter MUST send only the last events
  that do not require the previous events affecting the same Subject Principal to
  be processed by the Receiver, because the previous events are either cancelled
  by the later events or the previous events are outdated.

disabled

> The Transmitter MUST NOT transmit events over the stream, and will not hold
  any events for later transmission.

The following is a non-normative example request to check an event stream’s
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
  "status": "enabled"
}
~~~
{: title="Example: Check Stream Status Response" #figstatusresp}

The following is a non-normative example request to check an event stream's
status for a specific subject:

~~~ http
GET /ssf/status?stream_id=f67e39a0a4d34d56b3aa1bc4cff0069f&subject=<url-encoded-subject> HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=
~~~
{: title="Example: Check Stream Status Request with Subject" #figstatuswithsubjectreq}

The following is a non-normative example response with a Subject claim:

~~~
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "status": "enabled",
  "subject": {
    "tenant" : {
      "format" : "iss_sub",
      "iss" : "http://example.com/idp1",
      "sub" : "1234"
    }
  }
}
~~~
{: title="Example: Check Stream Status Response" #figstatuswithsubjectresp}

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 401  | if authorization failed or it is missing |
| 403  | if the Event Receiver is not allowed to read the stream status |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver, or if the Subject specified is invalid or if the Receiver is not authorized to get status for the specified Subject. |
{: title="Read Stream Status Errors" #tabreadstatus}

Examples:

1. If a Receiver makes a request with an invalid OAuth token, then the
   Transmitter MUST respond with a 401 error status.
2. If the Receiver presents a valid OAuth token, but the Transmitter policy
   does not permit the Receiver from obtaining the status, then the Transmitter
   MAY respond with a 403 error status.
3. If the Receiver requests the status for a stream that does not exist then the
   Transmitter MUST respond with a 404 error status.
4. If the Receiver requests the status for a specific Subject, but the
   Transmitter policy does not permit the Receiver to read the status of that
   Subject, then the Transmitter MAY respond with a 404 error status in order
   to not reveal the policy decision.
5. If the specified Subject is invalid then the Transmitter MUST respond with a
   404 error status.

#### Updating a Stream's Status {#updating-a-streams-status}
An Event Receiver updates the current status of a stream by making an HTTP POST
request to the Status Endpoint. The POST body contains a [JSON][RFC7159] object
with the following fields:

stream_id

> REQUIRED. The stream whose status is being updated.

status

> REQUIRED. The new status of the Event Stream.

subject

> OPTIONAL. The Subject to which the new status applies.

reason

> OPTIONAL. A short text description that explains the reason for the change.

On receiving a valid request the Event Transmitter responds with a "200 OK"
response containing a [JSON][RFC7159] representation of the updated stream
status in the body.

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
{: title="Example: Update Stream Status Request Without Optional Fields" #figupdatestatusreq}

The following is a non-normative example of an Update Stream Status request with
optional fields:

~~~ http
POST /ssf/status HTTP/1.1
Host: transmitter.example.com
Authorization: Bearer eyJ0b2tlbiI6ImV4YW1wbGUifQo=

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "status": "paused",
  "subject": {
    "tenant" : {
      "format" : "iss_sub",
      "iss" : "http://example.com/idp1",
      "sub" : "1234"
    }
  },
  "reason": "Disabled by administrator action."
}
~~~
{: title="Example: Update Stream Status Request With Optional Fields" #figupdatestatuswithsubjectreq}

The following is a non-normative example response:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
  "status": "paused",
  "subject": {
    "format" : "email",
    "email" : "user@example.com"
  }
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
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver, or if an invalid Subject is specified. |
{: title="Update Stream Status Errors" #tabupdatestatus}


Example:

1. If a Receiver makes a request to update a stream to enable it for a specific
   Subject, and the Transmitter is unable to decide whether or not to complete
   the request, then the Transmitter MUST respond with a 202 status code.

### Subjects {#subjects}
An Event Receiver can indicate to an Event Transmitter whether or not the
receiver wants to receive events about a particular subject by “adding” or
“removing” that subject to the Event Stream, respectively.

#### Adding a Subject to a Stream {#adding-a-subject-to-a-stream}
To add a subject to an Event Stream, the Event Receiver makes an HTTP POST
request to the Add Subject Endpoint, containing in the body a JSON object the
following claims:

stream_id

> REQUIRED. The stream to which the subject is being added.

subject

> REQUIRED. A Subject claim identifying the subject to be added.

verified

> OPTIONAL.  A boolean value; when true, it indicates that the Event Receiver
  has verified the Subject claim. When false, it indicates that the Event
  Receiver has not verified the Subject claim. If omitted, Event Transmitters
  SHOULD assume that the subject has been verified.

On a successful response, the Event Transmitter responds with an empty "200 OK"
response.  The Event Transmitter MAY choose to silently ignore the request, for
example if the subject has previously indicated to the Transmitter that they do
not want events to be transmitted to the Event Receiver. In this case, the
transmitter MAY return an empty "200 OK" response or an appropriate error code.
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

> REQUIRED. The stream from which the subject is being removed.

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
stream. Event Receivers can request that a verification event be transmitted
over the Event Stream, allowing the receiver to confirm that the stream is
configured correctly upon successful receipt of the event. The acknowledgment of
a Verification Event also confirms to the Event Transmitter that end-to-end
delivery is working, including signature verification and encryption.

An Event Transmitter MAY send a Verification Event at any time, even if one was
not requested by the Event Receiver.

#### Verification Event {#verification-event} 
The Verification Event is a standard SET with the following attributes:

event type

> The Event Type URI is: "https://schemas.openid.net/secevent/ssf/event-type/verification".

state

> OPTIONAL An opaque value provided by the Event Receiver when the event is
  triggered. This is a nested attribute in the event payload.

Upon receiving a Verification Event, the Event Receiver SHALL parse the SET and
validate its claims. In particular, the Event Receiver SHALL confirm that the
value for "state" is as expected. If the value of "state" does not match, an
error response of "setData" SHOULD be returned (see Section 2.3 of
{{DELIVERYPUSH}} or {{DELIVERYPOLL}}).

In many cases, Event Transmitters MAY disable or suspend an Event Stream that
fails to successfully verify based on the acknowledgement or lack of
acknowledgement by the Event Receiver.

#### Triggering a Verification Event. {#triggering-a-verification-event}
To request that a verification event be sent over an Event Stream, the Event
Receiver makes an HTTP POST request to the Verification Endpoint, with a [JSON]
[RFC7159] object containing the parameters of the verification request, if any.
On a successful request, the event transmitter responds with an empty
"204 No Content" response.

Verification requests have the following properties:

stream_id

> REQUIRED. The stream that the verification event is being requested on.

state

> OPTIONAL. An arbitrary string that the Event Transmitter MUST echo back to the
  Event Receiver in the verification event’s payload. Event Receivers MAY use
  the value of this parameter to correlate a verification event with a
  verification request. If the verification event is initiated by the transmitter
  then this parameter MUST not be set.

A successful response from a POST to the Verification Endpoint does not indicate
that the verification event was transmitted successfully, only that the Event
Transmitter has transmitted the event or will do so at some point in the future.
Event Transmitters MAY transmit the event via an asynchronous process, and SHOULD
publish an SLA for verification event transmission times. Event Receivers MUST NOT
depend on the verification event being transmitted synchronously or in any
particular order relative to the current queue of events.

Errors are signaled with HTTP status codes as follows:

| Code | Description |
|------|-------------|
| 400  | if the request body cannot be parsed or if the request is otherwise invalid |
| 401  | if authorization failed or it is missing |
| 404  | if there is no Event Stream with the given "stream_id" for this Event Receiver |
| 429  | if the Event Receiver is sending too many requests in a given amount of time; see related "min_verification_interval" in {{stream-config}}
{: title="Verification Errors" #taberifyerr}

The following is a non-normative example request to trigger a verification event:

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

And the following is a non-normative example of a verification event sent to the
Event Receiver as a result of the above request:

~~~ json
{
  "jti": "123456",
  "iss": "https://transmitter.example.com",
  "aud": "receiver.example.com",
  "iat": 1493856000,
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/verification":{
      "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="
    }
  }
}
~~~
{: title="Example: Verification SET" #figverifyset}

### Stream Updated Event {#stream-updated-event}
A Transmitter MAY change the stream status in reference to one or more Subjects
without a request from a Receiver. The Transmitter sends an event of type
"https://schemas.openid.net/secevent/ssf/event-type/stream-updated" to indicate
that it has changed the status of the Event Stream for a specific Subject.

If a Transmitter decides to change the status of an Event Stream from "enabled"
to either "paused" or "disabled", then the Transmitter MUST send this event to
any Receiver that is currently "enabled" to receive events from this stream.

If the Transmitter changes the status of the stream for a Subject from either
"paused" or "disabled" to "enabled", then it MUST send this event to any
Receiver that has previously been enabled to receive events for the specified
Subject.

The "stream-updated" event MAY contain the following claims:

status

> REQUIRED. Defines the new status of the stream for the Subject Identifier
  specified in the Subject.

reason

> OPTIONAL. Provides a short description of why the Transmitter has updated the
  status.

subject

> OPTIONAL. Specifies the Subject Principal for whom the status has been updated.
  If this claim is not included, then the status change was applied to all
  subjects in the stream.

~~~ json
{
  "jti": "123456",
  "iss": "https://transmitter.example.com",
  "aud": "receiver.example.com",
  "iat": 1493856000,
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/stream-updated": {
      "subject": {
        "tenant" : {
          "format": "iss_sub",
          "iss" : "http://example.com/idp1",
          "sub" : "1234"
        }    
      },   
      "status": "paused",
      "reason": "License is not valid"
    }   
  }
}
~~~
{: title="Example: Stream Updated SET" #figstreamupdatedset}

# Authorization {#management-api-auth}
HTTP API calls from a Receiver to a Transmitter SHOULD be authorized by
providing an OAuth 2.0 Access Token as defined by {{RFC6750}}.

The receiver may obtain an access token using the Client
Credential Grant {{CLIENTCRED}}, or any other method suitable for the Receiver and the
Transmitter.

# Security Considerations {#management-sec} 

## Subject Probing {#management-sec-subject-probing} 
It may be possible for an Event Transmitter to leak information about subjects
through their responses to add subject requests. A "404" response may indicate
to the Event Receiver that the subject does not exist, which may inadvertently
reveal information about the subject (e.g. that a particular individual does or
does not use the Event Transmitter’s service).

Event Transmitters SHOULD carefully evaluate the conditions under which they
will return error responses to add subject requests. Event Transmitters MAY
return a "204" response even if they will not actually send any events related
to the subject, and Event Receivers MUST NOT assume that a 204 response means
that they will receive events related to the subject.


## Information Harvesting {#management-sec-information-harvesting} 
SETs may contain personally identifiable information (PII) or other non-public
information about the event transmitter, the subject (of an event in the SET),
or the relationship between the two. It is important for Event Transmitters to
understand what information they are revealing to Event Receivers when
transmitting events to them, lest the event stream become a vector for
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
activity related to the subject, inconvenience the subject, or for other reasons.
Consequently it may be in the best interests of the subject for the Event
Transmitter to continue to send events related to the subject for some time after
the subject has been removed from a stream.

Event Transmitters MAY continue sending events related to a subject for some
amount of time after that subject has been removed from the stream. Event
Receivers MUST tolerate receiving events for subjects that have been removed
from the stream, and MUST NOT report these events as errors to the Event
Transmitter.


# Privacy Considerations {#privacy-considerations} 

## Subject Information Leakage {#sub-info-leakage} 
Event issuers and recipients SHOULD take precautions to ensure that they do not
leak information about subjects via Subject Identifiers, and choose appropriate
Subject Identifier Types accordingly. Parties SHOULD NOT identify a subject
using a given Subject Identifier Type if doing so will allow the recipient to
correlate different claims about the subject that they are not known to already
have knowledge of. Transmitters and Receivers SHOULD always use the same Subject
Identifier Type and the same claim values to identify a given subject when
communicating with a given party in order to reduce the possibility of
information leakage.

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
If a user has previously agreed with a Transmitter that they agree to release
certain data to third-parties, then the Transmitter MAY send such data in SSF
events without additional consent of the user. Such data MAY include
organizational data about the Subject Principal that was generated by the
Transmitter.

### Consentable Data {#consentable-data} 
If a Transmitter intends to include data in SSF events that is not previously
consented to be released by the user, then the Transmitter MUST obtain consent
to release such data from the user in accordance with the Transmitter's privacy
policy.

# Profiles {#profiles} 
This section is a profile of the following IETF SecEvent specifications:

* Security Event Token (SET) {{RFC8417}} 
* Push-Based SET Token Delivery Using HTTP {{DELIVERYPUSH}}
* Poll-Based SET Token Delivery Using HTTP {{DELIVERYPOLL}}

The RISC use cases that set the requirements are described in Security Events
RISC Use Cases {{USECASES}}.

The CAEP use cases that set the requirements are described in CAEP Use Cases (TODO: Add
        reference when file is added to repository.)

## Security Event Token Profile {#set-profle} 
This section provides SSF profiling specifications for the Security Event Token (SET)
{{RFC8417}} spec.

### Signature Key Resolution {#signature-key-resolution} 
The signature key can be obtained through "jwks_uri", see {{discovery}}.

### SSF Event Subject {#event-subjects} 
The subject of a SSF event is identified by the "subject" claim within the event
payload, whose value is a Subject Identifier. The "subject" claim is REQUIRED
for all SSF events. The JWT "sub" claim MUST NOT be present in any SET containing
a SSF event.

### SSF Event Properties {#event-properties} 
The SSF event MAY contain additional claims within the event payload that are
specific to the event type.

~~~ json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "aud": "636C69656E745F6964",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled": {
      "subject": {
        "format": "phone",
        "phone_number": "+1 206 555 0123"
      },
      "reason": "hijacking",
      "cause-time": 1508012752
    }
  }
}
~~~
{: #risc-event-subject-example title="Example: SET Containing a RISC Event with a Phone Number Subject"}

~~~ json
{
  "iss": "https://idp.example.com/",
  "jti": "756E69717565206964656E746966696572",
  "iat": 1520364019,
  "aud": "636C69656E745F6964",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-changed": {
      "subject": {
        "format": "email",
        "email": "user@example.com"
      },
      "token": "some-token-value"
    }
  }
}
~~~
{: #caep-event-properties-example title="Example: SET Containing a CAEP Event with Properties"}

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
Sections 4.5, 4.6 and 4.7 of {{RFC8417}}. While current Id Token {{IDTOKEN}}
validators may not be using the "typ" header parameter, by requiring it for SSF
SETs a distinct value is guaranteed for future validators.

### The "exp" Claim {#exp-claim} 
The "exp" claim MUST NOT be used in SSF SETs.

The purpose is defense in depth against confusion with other JWTs, as described
in Sections 4.5 and 4.6 of {{RFC8417}}.

### The "aud" Claim {#aud-claim} 
The "aud" claim can be a single value or an array. Each value SHOULD be the
OAuth 2.0 client ID. Other values that uniquely identifies the Receiver to the
Transmitter MAY be used, if the two parties have agreement on the format.

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
  "events": {
    "https://schemas.openid.net/secevent/ssf/event-type/verification": {
      "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo="
    }
  }
}
~~~
{: title="Example: SET with array 'aud' claim" #figarrayaud}

### The "events" claim {#events-claim} 
The "events" claim SHOULD contain only one event. Multiple event type URIs are
permitted only if they are alternative URIs defining the exact same event type.

### Security Considerations

#### Distinguishing SETs from other Kinds of JWTs
Of particular concern is the possibility that SETs are confused for other kinds
of JWTs. The Security Considerations section of {{RFC8417}} has several sub-sections
on this subject. The Shared Signals Framework is asking for further restrictions:

* The "sub" claim MUST NOT be present, as described in {{event-subjects}}.
* SSF SETs MUST use explicit typing, as described in {{explicit-typing}}.
* The "exp" claim MUST NOT be present, as described in {{exp-claim}}.

## SET Token Delivery Using HTTP Profile {#set-token-delivery-using-http-profile}
This section provides SSF profiling specifications for the {{DELIVERYPUSH}} and
{{DELIVERYPOLL}} specs.

### Stream Configuration Metadata {#delivery-meta} 
Each delivery method is identified by a URI, specified below by the "method"
metadata.

#### Push Delivery using HTTP
This section provides SSF profiling specifications for the {{DELIVERYPUSH}} spec.

method

> "https://schemas.openid.net/secevent/risc/delivery-method/push"

endpoint_url

> The URL where events are pushed through HTTP POST. This is set by the
  Receiver. If a Reciever is using multiple streams from a single Transmitter
  and needs to keep the SETs separated, it is RECOMMENDED that the URL for each
  stream be unique.

authorization_header

> The HTTP Authorization header that the Transmitter MUST set with each event
  delivery, if the configuration is present. The value is optional and it is set
  by the Receiver.
  
#### Polling Delivery using HTTP
This section provides SSF profiling specifications for the {{DELIVERYPOLL}} spec.

method

> "https://schemas.openid.net/secevent/risc/delivery-method/poll"

endpoint_url

> The URL where events can be retrieved from. This is specified by the
  Transmitter. These URLs MAY be reused across Receivers, but MUST be unique per
  stream for a given Receiver.

# IANA Considerations {#iana} 
Subject Identifiers defined in this document will be added to the "Security
Events Subject Identifier Types" registry. This registry is defined in the
Subject Identifiers for Security Event Tokens {{SUBIDS}} specification.

--- back

# Acknowledgements

The authors wish to thank all members of the OpenID Foundation SSF
Working Group who contributed to the development of this
specification.

# Notices

Copyright (c) 2021 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.
