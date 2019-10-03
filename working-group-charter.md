# RISC WG Charter
## 1) Working Group Name
Risk and Incident Sharing and Coordination Working Group [RISC]

## 2) Purpose
The goal of RISC is to provide data sharing schemas, privacy recommendations and protocols to:

* Share information about important security events in order to thwart attackers from leveraging compromised accounts from one Service Provider to gain access to accounts on other Service Providers (mobile or web application developers and owners).
* Enable users and providers to coordinate in order to securely restore accounts following a compromise.

Internet accounts that use email addresses or phone numbers as the primary identifier for the account will be the initial focus.

## 3) Scope
The group will define:

* **Security events**
  * These are events – whether directly authentication-related or occurring at another time in the user flow – that take place on one service that could also have security implications on other Service Providers. The group will develop a taxonomy of security events and a common set of semantics to express relevant information about a security event.
* **Privacy Implications**
  * Sharing security information amongst providers has potential privacy implications for both end users and service providers. These privacy implications must be considered against both (a) applicable regulations, policies, and the principles of user notice, choice and consent, and (b) the recognized benefits of protecting users’ accounts and data from abuse. The group will consider ways to address such potential privacy implications when defining mechanisms to handle the various security events and recommend best practices for the industry.
* **Communications mechanisms**
  * Define bindings for the use of an existing transport protocol defined elsewhere.
* **Trust Frameworks**
  * Define at least one model for the conditions under which information would be shared.
* **Event schema**
  * Define a schema describing relevant events and relationships to allow for dissemination between interested and authorized parties.
* **Account recovery mechanisms**
  * Standardized mechanism(s) to allow providers to signal that a user has regained control of an account, or allow a user to explicitly restore control of a previously compromised account, with or without direct user involvement.

### Out of scope:
* Determining the account quality/reputation of a user on a particular service and communicating that to others.
* Definition of APIs and underlying mechanisms for connecting to, interacting with and operating centralized databases or intelligence clearinghouses when these are used to communicate security events between account providers.

## 4) Proposed Deliverables
The group proposes the following **Non-Specification** deliverables:

* **Security Event and Account Lifecycle Schema**
  * A taxonomy of security events and a common set of semantics to express relevant information about a security event and its relationships to other relevant data, events or indicators.
* **Security Event Privacy Guidelines**
  * A set of recommendations on how to minimize the privacy impact on users and service providers while improving security, and how to provide appropriate privacy disclosures, labeling and access control guidelines around information in the Security Event Schema.
* **Trust Framework**
  * A trust framework defining roles and responsibilities of parties sharing user security event information

The group proposes the following **Specification** deliverables:

* **Communications Mechanisms**
  * Define bindings for the event messages to an already existing transport protocol to promote interoperability of sending event information to another Service Provider. This will allow a Service Provider to implement a single piece of infrastructure that would be able to send or receive event information to any other service provider.

### Order of Deliverables
The group will work to produce the Security Event and Account Lifecycle Schema before beginning work on the Communications Mechanism or Trust Framework.

## 5) Anticipated audience or users
* Service Providers who manage their own account systems which require an email address or phone number for registration.
* Account and email providers that understand key security events that happen to a user’s account.
* Identity as a Service (IDaaS) vendors that manage account and authentication systems for their customers.
* Users seeking to regain control of a compromised account.

## 6) Language
* English

## 7) Method of work:
* E-mail discussions on the working group mailing list, working group conference calls, and face-to-face meetings from time to time.

## 8) Basis for determining when the work is completed:
* Rough consensus and running code. The work will be completed once it is apparent that maximal consensus on the draft has been achieved, consistent with the purpose and scope.

# Background information
## Related work:
* RFC6545 Real-time Inter-network Defense (RID)
* RFC6546 Transport of Real-time Inter-network Defense (RID) Messages over HTTP/TLS
* RFC6684 Guidelines and Template for Defining Extensions to the Incident Object Description Exchange Format (IODEF)
* draft-ietf-mile-rolie Resource-Oriented Lightweight Indicator Exchange
* ISO/IEC 27002:2013  Information technology — Security techniques — Code of practice for information security controls
* ISO/IEC 27035:2011 Information technology — Security techniques — Information security incident management

## Proposers
* Adam Dawes, Google
* Mark Risher, Google
* George Fletcher, AOL
* Andrew Nash, Confyrm
* Nat Sakimura, Nomura Research Institute
* John Bradley, Ping Identity
* Alex Weinert, Microsoft
* Vicente Silveira, LinkedIn
* Henrik Biering, Peercraft

## Anticipated contributions:
“Security event reporting between Service Providers 1.0” under the [OpenID Foundation’s IPR Policy](http://openid.net/intellectual-property/).
