---
title: CAEP Interoperability Profile 1.0 - draft 02
abbrev: caep-interop
docname: caep-interoperability-profile-1_0

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
        org: Crowdstrike
        email: atul.tulshibagwale@crowdstrike.com
      -
        ins: A. Deshpande
        name: Apoorva Deshpande
        org: Okta
        email: apoorva.deshpande@okta.com
      -
        ins: J. Schreiber
        name: Jen Schreiber
        org: Crowdstrike
        email: jen.schreiber@crowdstrike.com

normative:
  RFC2119:
  RFC8174:
  RFC8417:
  RFC9493: # Subject Identifier Formats for SETs
  RFC8935: # Push delivery
  RFC8936: # POLL delivery
  SSF:
    target: https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
    title: OpenID Shared Signals Framework Specification 1.0
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
        ins: J. Bradley
        name: John Bradley
        org: Yubico
      -
        ins: S. Miel
        name: Shayne Miel
        org: Cisco

  CAEP:
    target: https://openid.net/specs/openid-caep-1_0-final.html
    title: OpenID Continuous Access Evaluation Profile 1.0
    author:
      -
        ins: T. Cappalli
        name: Tim Cappalli
        org: Microsoft
      -
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
        org: SGNL
  RFC9325: # Recommendations for Secure Use of TLS and DTLS
  RFC6125: # Representation and Verification of Domain-Based Application
           # Service Identity within Internet Public Key Infrastructure Using
           # X.509 (PKIX) Certificates in the Context of TLS
  RFC6750: # The OAuth 2.0 Authorization Framework: Bearer Token Usage
  RFC8414: # OAuth 2.0 Authorization Server Metadata
  RFC6749:
  FAPI:
    target: https://openid.net/specs/fapi-security-profile-2_0-final.html
    title: FAPI 2.0 Security Profile
    author:
      - ins: D. Fett
      - ins: D. Tonge
      - ins: J. Heenan
  OPRM:
    target: https://datatracker.ietf.org/doc/html/rfc9728
    title: OAuth 2.0 Protected Resource Metadata
    author:
      -ins: M.B. Jones
      -ins: P. Hunt
      -ins: A. Parecki

--- abstract
This document defines an interoperability profile for implementations of the
Shared Signals Framework ({{SSF}}) and the Continuous Access Evaluation
Profile ({{CAEP}}). It specifies required attributes for SSF endpoints, how to
use OAuth 2.0 {{RFC6749}} for their authorization, and the core use cases
to improve security of authenticated sessions. When implemented, the profile
enables seamless interoperability between SSF Transmitters and Receivers.

--- middle

# Introduction {#introduction}

The Shared Signals Framework enables sharing of Security Event Tokens (SETs)
{{RFC8417}} between cooperating peers. When combined with Continuous Access
Evaluation Profile ({{CAEP}}) to share events such as Session Revocation and
Credential Change, implementations can greatly improve their session and
security outcomes.

The CAEP Interoperability Profile outlines the minimum required features that
implementations must offer in order to be considered compliant and to achieve
interoperability. It describes specific use cases with CAEP session-revoked,
credential-change, and device-compliance-change events. Support for all use
cases listed herein is not required in order to be considered compliant with
this profile. An implementation can choose specific use cases to support.

The following specifications are profiled in this document:

* Shared Signals Framework Specification 1.0 {{SSF}}
* Continuous Access Evaluation Profile 1.0 ({{CAEP}})
* OAuth 2.0 {{RFC6749}}

## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Common Requirements {#common-requirements}

The following requirements are common across all use-cases defined in this
document.

## Network layer protection

* The SSF Transmitter MUST offer TLS protected endpoints and MUST establish
connections to other servers using TLS. TLS connections MUST be set up to use
TLS version 1.2 or later.
* The SSF Transmitter MUST follow the recommendations for Secure Use of
Transport Layer Security in [RFC9325]{{RFC9325}}.
* The SSF receiver MUST perform TLS server certificate signature checks, chain
of trust validations, expiry and revocation status checks before calling the SSF
Transmitter APIs, as per [RFC6125]{{RFC6125}}.

## CAEP specification version

This specification supports CAEP {{CAEP}} events from OpenID Continuous Access
Evaluation Profile 1.0.

## Transmitters {#common-transmitters}

Transmitters MUST implement the following features.

### Spec Version {#spec-version}

The Transmitter Configuration Metadata MUST include a `spec_version` field, and
its value MUST be `1_0` or greater.

### Delivery Method {#delivery-method}

The Transmitter Configuration Metadata MUST include the
`delivery_methods_supported` field.

### JWKS URI {#transmitter-jwks-uri}

The Transmitter Configuration Metadata MUST include the `jwks_uri` field, and
upon resolution, its value MUST provide the current signing key(s) of the
Transmitter.

### Configuration Endpoint {#configuration-endpoint}

The Transmitter Configuration Metadata MUST include the `configuration_endpoint`
field as defined in {{SSF}} Section 7.1.

The endpoint identified by `configuration_endpoint` is used to perform the
Create Stream operation as defined in {{SSF}} Section 8.1.1.

### Status Endpoint {#status-endpoint}

The Transmitter Configuration Metadata MUST include the `status_endpoint` field.

The endpoint identified by status_endpoint MUST support the Read Stream Status
(HTTP GET) operation as defined in {{SSF}} Sections 8.1.2.1.

### Verification Endpoint {#verification-endpoint}

The Transmitter Configuration Metadata MUST include the `verification_endpoint`
field.

The endpoint identified by `verification_endpoint` MUST support Stream
Verification as defined in {{SSF}} Section 8.1.4.

### Authorization Schemes

The Transmitter Configuration Metadata MUST include the `authorization_schemes`
field and its value MUST include the value:

```json
{
  "spec_urn": "urn:ietf:rfc:6749"
}
```

### Streams {#transmitter-common-stream-configuration}

Transmitters MUST support all required properties and API contracts defined by
{{SSF}} Stream Management API operations, in addition to the requirements
specified in this section.

For all Stream Management API requests received by the Transmitter, the
following MUST be true.

#### Delivery {#transmitter-common-delivery}

The Transmitter MUST support Create Stream requests whose `delivery.method` is
set to one of the following values:

* `urn:ietf:rfc:8935` (Push)
* `urn:ietf:rfc:8936` (Poll)

When a Receiver makes a Create Stream request as defined in {{SSF}} Section
8.1.1.1 with valid authorization, the Transmitter MUST process the request as
specified in {{SSF}}.

Upon successful creation of a Stream, the Transmitter MUST include a `delivery`
field in the resulting Stream Configuration, and its `method` value MUST be one
of the delivery methods listed above.

#### Stream Control

**Create Stream**
: The Transmitter MUST support the Create Stream operation as defined in
{{SSF}} Section 8.1.1.1 when invoked by a Receiver with valid authorization.

**Read Stream Configuration**
: The Transmitter MUST support the Read Stream Configuration operation as
defined in {{SSF}} Section 8.1.1.2 when invoked by a Receiver with valid
authorization.

**Get Stream Status**
: The Transmitter MUST support the Read Stream Status operation as defined in
{{SSF}} Section 8.1.2.1 when invoked by a Receiver with valid authorization.

**Stream Verification**
: The Transmitter MUST support Stream Verification as defined in
{{SSF}} Section 8.1.4.2 and MUST generate a Verification Event as defined in
{{SSF}} Section 8.1.4.1 when requested by a Receiver with valid authorization.

**Deleting a Stream**
: The Transmitter MUST support the Delete Stream operation as defined in
{{SSF}} Section 8.1.1.5 when invoked by a Receiver with valid authorization.

## Receivers {#common-receivers}

Receivers MUST implement the following features.

### Delivery Methods {#common-receiver-delivery}

Receivers MUST be able to accept events using any one of the two delivery
methods:

* Push-Based Security Event Token (SET) Delivery Using HTTP {{RFC8935}}
* Poll-Based Security Event Token (SET) Delivery Using HTTP {{RFC8936}}

### JWKS URI {#receiver-jwks-uri}

The Receiver MUST obtain the Transmitter’s signing key(s) using the `jwks_uri`
from the Transmitter Configuration Metadata, as defined in {{SSF}} Section 7.1.

### Authorization Schemes {#receivers-authorization-schemes}

The Receiver MUST use OAuth 2.0 {{RFC6749}} when making Stream Management API
requests to the Transmitter.

### Implicitly Added Subjects {#common-receiver-subjects}

The Receiver MUST assume that all subjects are implicitly included in a Stream,
without any `AddSubject` method invocations.

### Streams {#receiver-common-stream-configuration}

Receivers MUST support all required properties and API contracts defined by
{{SSF}} Stream Management API operations, in addition to the requirements
specified in this section.

For Stream Management API requests initiated by the Receiver, and for Streams
created by the Receiver, the following MUST be true.

#### Delivery {#common-delivery}

When creating a Stream using the Create Stream operation defined in {{SSF}}
Section 8.1.1.1, the Receiver MUST include a `delivery` object whose `method`
value is one of the following, or omit the `delivery` object.

* `urn:ietf:rfc:8935` (Push)
* `urn:ietf:rfc:8936` (Poll)

If the Create Stream request does not include the `delivery` property, it is
assumed to be delivery method of `urn:ietf:rfc:8936` (Poll), as
defined in {{SSF}}.

#### Stream Control {#receivers-stream-control}

The following Stream Management operations MUST be supported by the Receiver.

**Create Stream**
: The Receiver MUST be able to invoke the Create Stream operation as defined in
{{SSF}} Section 8.1.1.1 using valid authorization.

**Read Stream Configuration**
: The Receiver MUST be able to invoke the Read Stream Configuration operation as
defined in {{SSF}} Section 8.1.1.2 using valid authorization.

**Get Stream Status**
: The Receiver MUST be able to invoke the Read Stream Status operation as
defined in {{SSF}} Section 8.1.2.1 using valid authorization.

**Stream Verification**
: The Receiver MUST be able to initiate Stream Verification as defined in
{{SSF}} Section 8.1.4.2 using valid authorization, and MUST be able to process
the resulting Verification Event as defined in {{SSF}} Section 8.1.4.1.

**Deleting a Stream**
: The Receiver MUST be able to invoke the Delete Stream operation as defined in
{{SSF}} Section 8.1.1.5 using valid authorization.

## Event Subjects {#common-event-subjects}

The following subject identifier formats from "Subject Identifiers for Security
Event Tokens" {{RFC9493}} MUST be supported:

* `email`
* `iss_sub`
* `opaque` (for the Verification event only)

Receivers MUST be prepared to accept events with any of the subject identifier
formats specified in this section. Transmitters MUST be able to send events with
at least one of subject identifier formats specified in this section.

## Event Signatures

All events MUST be signed using the `RS256` algorithm using a minimum of
2048-bit keys.

## OAuth Service

### Authorization Server

An OAuth {{RFC6749}} Authorization Server issues access tokens. In the context
of this profile, the Authorization Server that issues access tokens can be a
separate entity than the SSF Transmitter.

* The Authorization Server MAY distribute discovery metadata (such as the
authorization endpoint) via Authorization Server Metadata as specified in
[RFC8414]{{RFC8414}}
* The Authorization Server MUST support at least one of the following to issue a
short-lived access token to the Receiver
  * client credential grant flow {{RFC6749}} section 4.4
  * authorization code flow {{RFC6749}} section 4.1

A short lived access token is defined as one in which the value of the
`exp` claim is not longer than 60 minutes after `nbf` claim. Please refer to
access token lifetimes in the security considerations of {{FAPI}} for additional
considerations.

### OAuth Scopes

Depending on the features supported by the OAuth service and the SSF APIs, the
OAuth Client SHALL discover the OAuth scopes as follows:

* If the Resource Server, hosting SSF configuration APIs, supports OAuth
Protected Resource Metadata {{OPRM}} then the client MUST obtain the required
scopes by using it.

* If the Resource Server does not support {{OPRM}}, then the following scopes
MUST be supported:

  * An OAuth {{RFC6749}} Authorization Server that is used to issue tokens to
  SSF Receivers, MUST reserve the scopes for the SSF endpoints with the prefix
  of `ssf`
  * All the SSF stream configuration management API operations MUST accept
  `ssf.manage` scope
  * All the SSF stream configuration Read API operations MUST accept `ssf.read`
  scope

### The SSF Transmitter as a Resource Server

* MUST accept access tokens in the HTTP header as in Section 2.1 of OAuth 2.0
Bearer Token Usage [RFC6750]{{RFC6750}}
* MUST NOT accept access tokens in the query parameters stated in Section 2.3 of
OAuth 2.0 Bearer Token Usage [RFC6750]{{RFC6750}}
* MUST verify the validity, integrity, expiration and revocation status of
access tokens
* MUST verify that the authorization represented by the access token is
sufficient for the requested resource access.
* If the access token is not sufficient for the requested action, the Resource
server MUST return errors as per section 3.1 of [RFC6750]{{RFC6750}}
* MAY publish the {{OPRM}} to describe the metadata needed to interact with the
protected resource.

## Security Event Token

### The "events" claim

The "events" claim of the SET MUST contain only one event.

# Use Cases

Implementations MAY choose to support one or more of the following use-cases in
order to be considered an interoperable implementation.

## Session Revocation / Logout

In order to support session revocation or logout, implementations MUST support
the CAEP event type `session-revoked`. The `reason_admin` field of the event
MUST be populated with a non-empty value.

## Credential Change

In order to support notifying and responding to credential changes,
implementations MUST support the CAEP event type `credential-change`.
Within the `credential-change` event, implementations MUST support the following
field values:

`change_type`
: Receivers MUST interpret all allowable values of this field. Transmitters MAY
generate any allowable value of this field

`credential_type`
: Receivers MUST interpret all allowable values of this field. Transmitters MAY
generate any allowable value of this field

`reason_admin`
: Transmitters MUST populate this value with a non-empty string

## Device Compliance Change

In order to support notifying and responding to changes in device compliance
status, implementations MUST support the event type `device-compliance-change`.
This event is used to signal that a device's adherence to a set of security or
organizational compliance policies has changed. Implementations MUST support
the following field values:

`previous_status`
: Receivers MUST interpret all allowable values of this field. Transmitters MAY
generate any allowable value of this field

`current_status`
: Receivers MUST interpret all allowable values of this field. Transmitters MAY
generate any allowable value of this field

`reason_admin`
: Transmitters MUST populate this value with a non-empty string

# Security Considerations

There are no additional security considerations that arise from this document.
These are covered in the "Security Considerations" sections of {{SSF}} and
{{CAEP}} specifications.

--- back

# Acknowledgements

The authors wish to thank all members of the OpenID Foundation Shared Signals
Working Group who contributed to the development of this
specification.

# Notices

Copyright (c) 2025 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer,
or other interested party a non-exclusive, royalty free, worldwide copyright
license to reproduce, prepare derivative works from, distribute, perform and
display, this Implementers Draft or Final Specification solely for the purposes
of (i) developing specifications, and (ii) implementing Implementers Drafts and
Final Specifications based on such documents, provided that attribution be made
to the OIDF as the source of the material, but that such attribution does not
indicate an endorsement by the OIDF.

The technology described in this specification was made available from
contributions from various sources, including members of the OpenID Foundation
and others. Although the OpenID Foundation has taken steps to help ensure that
the technology is available for distribution, it takes no position regarding the
validity or scope of any intellectual property or other rights that might be
claimed to pertain to the implementation or use of the technology described in
this specification or the extent to which any license under such rights might or
might not be available; neither does it represent that it has made any
independent effort to identify any such rights. The OpenID Foundation and the
contributors to this specification make no (and hereby expressly disclaim any)
warranties (express, implied, or otherwise), including implied warranties of
merchantability, non-infringement, fitness for a particular purpose, or title,
related to this specification, and the entire risk as to implementing this
specification is assumed by the implementer. The OpenID Intellectual Property
Rights policy requires contributors to offer a patent promise not to assert
certain patent claims against other contributors and against implementers. The
OpenID Foundation invites any interested party to bring to its attention any
copyrights, patents, patent applications, or other proprietary rights that may
cover technology that may be required to practice this specification.

# Document History

  [[ To be removed from the final specification ]]

-02

* Updated required SSF spec version to 1_0
* Updated spec references (#291)

-01

* Cleaned up markdown (#91)

-00

* Initial draft