---
title: CAEP Interoperability Profile 1.0 - draft 01
abbrev: caep-interop
docname: caep-interoperability-profile-1_0
date: 2023-11-17

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

contributor:
      -
        ins: A. Deshpande
        name: Apoorva Deshpande
        org: Okta
        email: apoorva.deshpande@okta.com

normative:
  RFC9493: # Subject Identifier Formats for SETs
  RFC8935: # Push delivery
  RFC8936: # POLL delivery
  SSF:
    target: https://openid.net/specs/openid-sharedsignals-framework-1_0.html
    title: OpenID Shared Signals and Events Framework Specification 1.0 - draft 02
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
    target: https://openid.net/specs/openid-caep-specification-1_0.html
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


--- abstract
This document defines an interoperability profile for implementations of the Shared Signals Framework (SSF) {{SSF}} and the Continuous Access Evaluation Profile (CAEP) {{CAEP}}. It is organized around use-cases that improve security of authenticated sessions. It specifies certain optional elements from within the SSF and CAEP specifications as being required to be supported in order to be considered as an interoperable implementation.

--- middle

# Introduction {#introduction}
SSF and CAEP together enable improved session security outcomes. This specification defines the minimum required features from SSF and CAEP that an implementation MUST offer in order to be considered as an interoperable implementation. This document defines specific use cases. An implementation MAY support only a subset of the use cases defined herein, and SHALL be considered an interoperable implementation for the specific use-cases it supports. The following use-cases are considered as a part of this specification:

Session Revocation
: A SSF Transmitter or Receiver is able to respectively generate or respond to the CAEP session-revoked event

Credential Change
: A SSF Transmitter or Receiver is able to respectively generate or respond to the CAEP credential-change event

# Common Requirements {#common-requirements}
The following requirements are common across all use-cases defined in this document.

## Transmitters {#common-transmitters}
Transmitters MUST implement the following features:

### Spec Version {#spec-version}
The Transmitter Configuration Metadata MUST have a `spec_version` field, and its value MUST be `1_0-ID2` or greater

### Delivery Method {#delivery-method}
The Transmitter Configuration Metadata MUST include the `delivery_methods_supported` field.

### JWKS URI {#jwks-uri}
The Transmitter Configuration Metadata MUST include the `jwks_uri` field, and its value MUST provide the current signing key of the Transmitter.

### Configuration Endpoint {#configuration-endpoint}
The Transmitter Configuration Metadata MUST include the `configuration_endpoint` field. The specified endpoint MUST support the `POST` method in order to be able to create a stream.

### Status Endpoint {#status-endpoint}
The Transmitter Configuration Metadata MUST include the `status_endpoint` field. The specified endpoint MUST support the `GET` and `POST` methods in order to get and update the stream status respectively. The Transmitter MUST support the following values in an Update Stream Status request:

* `enabled`
* `paused`
* `disabled`

For streams that are `paused`, the Transmitter MUST specify (offline) the resource constraints on how many events it can keep, or for how long. The way a Transmitter specifies this information is outside the scope of the SSF spec.

### Verification Endpoint {#verification-endpoint}
The Transmitter Configuration Metadata MUST include the `verification_endpoint` field. The specified endpoint MUST provide a way to request verification events to be sent.

### Authorization Schemes
The Transmitter Configuration Metadata MUST include the `authorization_schemes` field and its value MUST include the value

~~~json
{
    "spec_urn": "urn:ietf:rfc:6749"
}
~~~

### Streams {#common-stream-configuration}
In all streams created by the Transmitter, the following MUST be true:

#### Delivery {#common-delivery}
A Transmitter MUST be able to accept a Create Stream request that includes either of the following delivery methods:

* urn:ietf:rfc:8935 (Push)
* urn:ietf:rfc:8936 (Poll)

The `delivery` field MUST be present in the Configuration of any Stream generated by the Transmitter, and its value MUST include one of the two delivery methods listed above.

#### Stream Control
The following Stream Configuration API Methods MUST be supported:

**Creating a Stream**
: Receivers MUST be able to create a Stream with the Transmitter using valid authorization with the Transmitter. The Transmitter MAY support multiple streams with the same Receiver

**Reading Stream Configuration**
: A Receiver MUST be able to obtain current Stream configuration from the Transmitter by providing a valid authorization

**Getting the Stream Status**
: A Receiver MUST be able to obtain the current Stream status from the Transmitter by providing a valid authorization

**Stream Verification**
: A Receiver MUST be able to verify the liveness of the Stream by requesting that the Transmitter send it a Stream Verificaiton event by providing a valid authorization

## Receivers {#common-receivers}
Receivers MUST implement the following features:

### Delivery Methods {#common-receiver-delivery}
Receivers MUST be able to accept events using the Push-Based Security Event Token (SET) Delivery Using HTTP {{RFC8935}} specification and the Poll-Based Security Event Token (SET) Delivery Using HTTP {{RFC8936}} specification.

### Implicitly Added Subjects {#common-receiver-subjects}
Receivers MUST assume that all subjects are implicitly included in a Stream, without any `AddSubject` method invocations.

## Event Subjects {#common-event-subjects}
The following subject identifier formats from "Subject Identifiers for Security Event Tokens" {{RFC9493}} MUST be supported:

* `email`
* `iss_sub`

Receivers MUST be prepared to accept events with any of the subject identifier formats specified in this section. Transmitters MUST be able to send events with at least one of subject identifier formats specified in this section.

## Event Signatures
All events MUST be signed using the `RS256` algorithm using a minimum of 2048-bit keys.

# Use Cases
Implementations MAY choose to support one or more of the following use-cases in order to be considered interoperable implementations

## Session Revocation / Logout
In order to support session revocation or logout, implementations MUST support the CAEP event type `session-revoked`. The `reason_admin` field of the event MUST be populated with a non-empty value.

## Credential Change
In order to support notifying and responding to credential changes, implementations MUST support the CAEP event type `credential-change`.
Within the `credential-change` event, implementations MUST support the following field values:

`change_type`
: Receivers MUST interpret all allowable values of this field. Transmitters MAY generate any allowable value of this field

`credential_type`
: Receivers MUST interpret all allowable values of this field. Transmitters MAY generate any allowable value of this field

`reason_admin`
: Transmitters MUST populate this value with a non-empty string

