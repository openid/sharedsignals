---
title: OpenID Shared Signals Event Definition Specification
abbrev: SSFEvents-Spec
docname: openid-sharedsignals-eventdef-specification-1_0
date: 2024-10-22

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
        ins: J. Schreiber
        name: Jen Schreiber
        org: Workday
        email: jennifer.winer@workday.com
      -
        ins: A. Deshpande
        name: Apoorva Deshpande
        org: Okta
        email: apoorva.deshpande@okta.com
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
    target: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    title: OpenID Connect Core 1.0 - ID Token
  RFC2119:
  RFC8174:
  RFC5280:
  RFC5646:
  RFC6711:
  RFC8176:
  SSF:
    target: https://openid.net/specs/openid-sharedsignals-framework-1_0-03.html
    title: OpenID Shared Signals and Events Framework Specification 1.0
    author:
      -
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
        org: Google
      -
        ins: T. Cappalli
        name: Tim Cappalli
        org: Okta
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
  informative:
    JSONSchemaValidation: # would these two be normative?
      target: https://json-schema.org/draft/2020-12/json-schema-validation
      title: JSON Schema Validation: A Vocabulary for Structural Validation of JSON
      author:
      - ins: A. Wright
        name: Austin Wright
      - ins: H. Andrews
        name: Henry Andrews
      - ins: B. Hutton
        name: Ben Hutton
    JSONSchema:
      target: https://json-schema.org/draft/2020-12/json-schema-core
      title: JSON Schema: A Media Type for Describing JSON Documents
      author:
      - ins: A. Wright
        name: Austin Wright
      - ins: H. Andrews
        name: Henry Andrews
      - ins: B. Hutton
        name: Ben Hutton
      - ins: G. Dennis
        name: Greg Dennis

--- abstract

This document defines how to describe events for the Shared Signals Framework {{SSF}} using JSON Schema. It specifies how to translate normative requirements for event types into JSON Schema vocabulary and the process to register and discover new schemas.

--- middle

# Introduction {#introduction}

The Shared Signals Framework {{SSF}} enables sharing of signals and events between cooperating peers. It is currently leveraged by two applications – the Continuous Access Evaluation Profile {{CAEP}} and Risk Incident Sharing and Coordination {{RISC}}.

This specification defines how to translate normative SSF event requirements, such as from CAEP and RISC events, into a JSON Schema. {{JSONSchema}} is a standardized way to describe the structure, constraints, and data types within a JSON document. JSON Schemas are often used with {{JSONSchemaValidation}} to automatically check if a JSON document adheres to the defined schema, thus ensuring data integrity.

Using JSON Schema to describe SSF has the following benefits:
- Faster process to create, update and get approval for new event types
- Easy and appropriate format to describe event types, as opposed to traditional specification text
- Machine readability for creating and validating SSF event paylods
- Independent versioning to reduce the friction between the SSF core specification and event type publications
- Allows new SSF events to be incorporated into the SSF ecosystem

# JSON Schema Defintion

The following section describes how to map a SSF event to a JSON Schema Document.

As defined in Section 4.3 of {{JSON Schema}}, a JSON Schema document, also called a "schema", is a JSON document used to describe another JSON document, known as an instance.

A JSON Schema document describes the instance of SSF SET event "payload" (Section 2 of {{SET}}). As such, the schema will define the claims that pertain to the specific SSF event type. The $id for the schema document MUST be the same as the event identifier of the SET.

The schema is made up of the following top-level JSON keys:

\\$schema
: REQUIRED, JSON string: URI of the version of JSON Schema that this document adheres to. E.g., `https://json-schema.org/draft/2020-12/schema`. Normative Schema Keyword.

\\$id
: REQUIRED, JSON string: URI of the schema, also known as the Event Identifier of the SET appended in accordance with[Schema Ids](#schema-ids). MUST be publicly accessible or available out-of-band and resolve to JSON Schema document. Normative Schema Keyword.

title
: REQUIRED, JSON string: Title of the schema. Informational Schema Annotation.

description
: REQUIRED, JSON string: Intent of the schema. Informational Schema Annotation.

type
: REQUIRED JSON string: Defines the first constraint on the JSON data. MUST be "object". Normative Validation Keyword.

properties
: REQUIRED JSON object: Object that defines the keys in the JSON data that are being validated. Normative Validation Keyword.


The following is a non-normative example of the top level properties of a JSON Schema document for a Session Revoked CAEP event.
~~~ json
{
   "$schema":"https://json-schema.org/draft/2020-12/schema",
   "$id":"https://schemas.openid.net/secevent/caep/event-type/session-revoked/1.0.0/schema.json",
   "title":"Session Revoked",
   "description":"Session Revoked signals that the session identified by the subject has been revoked. The explicit session identifier may be directly referenced in the subject or other properties of the session may be included to allow the receiver to identify applicable sessions.",
   "type":"object",
   "properties":{...}
}
~~~

## Properties 

The top level "properties" key contains an object where each property represents a key in the JSON data being validated. Within each property, all normative requirements and non-normative details are specified by using the vocabulary in {{JSONSchemaValidation}}.

The following is a non-normative example of a "properties" object for a CAEP event schema.
~~~json
{
   "properties": {
    "initiating_entity": {
      "description": "Describes the entity that invoked the event.",
      "type": "string",
      "oneOf": [
        {
          "const": "admin",
          "description": "an administrative action triggered the event"
        },
        {
          "const": "user",
          "description": "an end-user action triggered the event"
        },
        {
          "const": "policy",
          "description": "a policy evaluation triggered the event"
        },
        {
          "const": "system",
          "description": "a system or platform assertion triggered the event"
        }
      ]
    },
    "required": [ "initiating_entity" ]
   }
}
~~~

## Full Example

The following is a non-normative example of the top level properties of a JSON Schema document for a Session Revoked CAEP event.
~~~ json
{
   "$schema":"https://json-schema.org/draft/2020-12/schema",
   "$id":"https://schemas.openid.net/secevent/caep/event-type/session-revoked/1.0.0/schema.json",
   "title":"Session Revoked",
   "description":"Session Revoked signals that the session identified by the subject has been revoked. The explicit session identifier may be directly referenced in the subject or other properties of the session may be included to allow the receiver to identify applicable sessions.",
   "type":"object",
   "properties":{
      "initiating_entity":{
         "description":"Describes the entity that invoked the event.",
         "type":"string",
         "oneOf":[
            {
               "const":"admin",
               "description":"an administrative action triggered the event"
            },
            {
               "const":"user",
               "description":"an end-user action triggered the event"
            },
            {
               "const":"policy",
               "description":"a policy evaluation triggered the event"
            },
            {
               "const":"system",
               "description":"a system or platform assertion triggered the event"
            }
         ]
      },
      "reason_admin":{
         "type":"object",
         "properties":{
            "en":{
               "type":"string"
            }
         }
      },
      "reason_user":{
         "type":"object",
         "properties":{
            "en":{
               "type":"string"
            },
            "es-410":{
               "type":"string"
            }
         }
      },
      "event_timestamp":{
         "type":"number"
      }
   }
}
~~~

# Registry

## Schema Ids

Ids of SSF event schemas MUST adhere the following convention:

{event type URI}/{semantic version}/schema.json

For example, the schema id for a session revoked caep event would be constructed by concatenating the following:
- event type uri: https://schemas.openid.net/secevent/caep/event-type/session-revoked
- semantic version: 1.0.0
- schema.json

The resulting id would be "https://schemas.openid.net/secevent/caep/event-type/session-revoked/1.0.0/schema.json"


## The Registration Process

SSF Implementers may find that existing registered SSF event types do not meet the needs of their applications. In that case, they may propose a new SSF event type and register its schema. To do so, an implementer MUST create a request in the form of a Pull Request to https://github.com/openid/sharedsignals following the PR Template and meeting the following requirements. The pull request will be reviewed by the Shared Signals Working Group and accepted at their discretion.

1. Author(s) of the pull request MUST be at least a contributing member of the OpenID Foundation.
1. The Pull Request MUST contain a human readable description of the new SSF event type.
1. The $id of the schema MUST be publicly accessible on the internet and resolve to the schema document.
1. The "title" and "description" of the schema must be meaningful and indicative of its function.
1. The naming of all schema properties MUST be indicative of its function.
1. Schemas should not be removed, only incremented (via semantic versioning) or marked as deprecated in the repositiory. Any changes to schemas must follow semantic versioning.

## Notational Considerations
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.


# Acknowledgements

The authors wish to thank all members of the OpenID Foundation Shared Signals Working Group who contributed to the development of this specification.

# Notices

Copyright (c) 2024 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.
