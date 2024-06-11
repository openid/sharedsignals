---
title: OpenID Shared Signals Event Definition Specification
abbrev: SSFEvents-Spec
docname: openid-sharedsignals-eventdef-specification-1_0
date: 2024-06-06

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
        org: Okta
        email: tim.cappalli@okta.com
      -
        ins: A. Deshpande
        name: Apoorva Deshpande
        org: Okta
        email: apoorva.deshpande@okta.com
      -
        ins: J. Schreiber
        name: Jen Schreiber
        org: Workday
        email: jennifer.winer@workday.com

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
  informative:
    JSONSchema:
      target: https://json-schema.org/draft/2020-12/json-schema-validation
      title: JSON Schema Validation: A Vocabulary for Structural Validation of JSON
      author:
      - ins: A. Wright
        name: Austin Wright
      - ins: H. Andrews
        name: Henry Andrews
      - ins: B. Hutton
        name: Ben Hutton

--- abstract

This document defines how to describe events for the Shared Signals Framework {{SSF}} using JSON Schema. It specifies how to translate normative requirements for event types into JSON Schema vocabulary and the process to register and discover these schemas.

--- middle

# Introduction {#introduction}

some text describing json schema
what it gives us

# JSON Vocabulary Transalation
# Schema for mandatory claims in SET

# Discoverability/Registry

## Event Types

| Event Type | Schema URI |
|------|-------------|
| CAEP  | <schema uri here> |
| RISC  |  <schema uri here>  |

{: title="Name this table..." #eventtypestable}

### CAEP

### RISC

# Process for raising PRs and getting approved

## Notational Considerations
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.


# Acknowledgements

The authors wish to thank all members of the OpenID Foundation Shared Signals Working Group who contributed to the development of this specification.

# Notices

Copyright (c) 2024 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.
