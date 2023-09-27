---
title: Shared Signals Versioning Proposal - draft 01
abbrev: SharedSignals-Versioning
docname: openid-sharedsignals-versioning-1_0
date: 2023-08-14
author:
      -
        ins: A. Tulshibagwale
        name: Atul Tulshibagwale
        org: SGNL
        email: atul@sgnl.ai
ipr: none
cat: std
wg: Shared Signals

--- abstract
This versioning proposal defines a numbering scheme for versions of all output of the OpenID Shared Signals Working Group

--- middle

# Background
The OpenID standardization process has three steps:

1. A draft spec is worked on in the working group
2. A draft spec is accepted by the OpenID Foundation as an “Implementer’s Draft”
3. An Implementer’s Draft is accepted by the OpenID Foundation as a Final Specification.


For the purposes of this document, the latest accepted Implementer’s Draft is called the “Latest Spec”.

## Protocol Versions
In the case of the Shared Signals Framework (SSF), a newer draft may change something about the protocol, i.e. the API, event formats, metadata formats, etc. These changes can be categorized as follows:

1. **No Change**: The new version makes no changes to the API, event formats or metadata formats or other properties of the protocol it describes that differs from the Latest Spec.
2. **Backward Compatible Change**: The new version adds optional properties or methods to the Latest Spec, but an implementation of the Latest Spec that does not implement the new features can continue to operate without seeing any difference in the behavior from the peer that has implemented some or all of the new optional properties.
3. **Breaking Change**: The new version makes changes to the Latest Spec. Implementations need to be updated in order to be able to work with any implementation of this new version.

**Note** that the change is always compared against the Latest Spec, and not against previous working group drafts.
Versioning Proposal
Version numbers are represented as decimal numbers, including at least one numeral after the decimal point even if it is the value “0”.

The Latest Spec version, although not specified in the metadata or anywhere else in the Latest Spec, is assumed to be “0.1”.

For all versions starting now (i.e. as of Aug 14, 2023), we will do the following:

1. Include a “version” field in the Transmitter Configuration Metadata
2. Keep the version number the same if it represents No Change
3. Increment the version number to the right of the decimal point if the new version represents a Backward Compatible Change
4. Increment the version number to the left of the decimal point and set the version number to the right of the decimal point to “0”, if the new version represents a Breaking change

**Note** that as a draft progresses through the standardization process, the version numbers do not change until the change is accepted as an Implementer’s Draft (therefore becoming a new Latest Spec). The version number does not change when the Latest Spec is accepted as a Final Specification. GitHub commits that are used to create a Latest Spec will be tagged to the version number of the corresponding document.

**Note** that it is possible for a Transmitter to support multiple versions by providing different endpoints that communicate using the version specified in the metadata of that collection of endpoints.

# Example
The current Latest Spec version is “0.1”. The draft currently being worked on will be called “1.0”. This number will remain unchanged if the current draft or some successor of it (regardless of whether the drafts have more Breaking Changes or Backward Compatible Changes) will remain “1.0” until it becomes an Implementer’s Draft.

Suppose a successive working group draft makes a Backward Compatible Change after the version of the Latest Spec is “1.0”, then the new working group draft will have the version number “1.1”. Even if successive versions of the working group draft make more Backward Compatible Changes, the version number will remain “1.1” until some working group draft becomes accepted as an Implementer’s Draft.

Suppose a successive working group draft after the Latest Spec version is “1.1” makes a Breaking Change, the new working group draft will be called “2.0”. Until this draft becomes the Latest Spec, regardless of how many more Breaking Changes occur in successive working group drafts, the version remains “2.0”.

Suppose the next Final Specification that is accepted is “1.1”, it does not change anything about the “2.0” number of the working group draft.

--- back

# Acknowledgements

The author wishes to thank all members of the OpenID Foundation Shared Signals Working Group who contributed to the development of this specification.

# Notices

Copyright (c) 2023 The OpenID Foundation.

The OpenID Foundation (OIDF) grants to any Contributor, developer, implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare derivative works from, distribute, perform and display, this Implementers Draft or Final Specification solely for the purposes of (i) developing specifications, and (ii) implementing Implementers Drafts and Final Specifications based on such documents, provided that attribution be made to the OIDF as the source of the material, but that such attribution does not indicate an endorsement by the OIDF.

The technology described in this specification was made available from contributions from various sources, including members of the OpenID Foundation and others. Although the OpenID Foundation has taken steps to help ensure that the technology is available for distribution, it takes no position regarding the validity or scope of any intellectual property or other rights that might be claimed to pertain to the implementation or use of the technology described in this specification or the extent to which any license under such rights might or might not be available; neither does it represent that it has made any independent effort to identify any such rights. The OpenID Foundation and the contributors to this specification make no (and hereby expressly disclaim any) warranties (express, implied, or otherwise), including implied warranties of merchantability, non-infringement, fitness for a particular purpose, or title, related to this specification, and the entire risk as to implementing this specification is assumed by the implementer. The OpenID Intellectual Property Rights policy requires contributors to offer a patent promise not to assert certain patent claims against other contributors and against implementers. The OpenID Foundation invites any interested party to bring to its attention any copyrights, patents, patent applications, or other proprietary rights that may cover technology that may be required to practice this specification.
