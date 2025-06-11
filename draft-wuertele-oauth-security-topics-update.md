---
title: "OAuth 2.0 Security Best Current Practice"
abbrev: "OAuth 2.0 Security BCP"
category: bcp
seriesno: 240
docname: draft-wuertele-oauth-security-topics-update-latest
updates: 6749, 6750, 7521, 7522, 7523, 9700

submissiontype: IETF
ipr: trust200902
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - security
 - oauth2
 - best current practice
venue:
  group: "Web Authorization Protocol"
  type: ""
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"
  github: "SECtim/draft-wuertele-oauth-security-topics-update"
  latest: "https://SECtim.github.io/draft-wuertele-oauth-security-topics-update/draft-wuertele-oauth-security-topics-update.html"

author:
 -
    fullname: "Tim Würtele"
    organization: University of Stuttgart
    email: tim.wuertele@sec.uni-stuttgart.de
    country: Germany
 -
    fullname: "Pedram Hosseyni"
    organization: University of Stuttgart
    email: pedram.hosseyni@sec.uni-stuttgart.de
    country: Germany
 -
    fullname: "Kaixuan Luo"
    organization: The Chinese University of Hong Kong
    email: kaixuan@ie.cuhk.edu.hk
    country: Hong Kong
 -
    fullname: "Adonis Fung"
    organization: Samsung Research America
    email: adonis.fung@samsung.com
    country: USA

normative:

informative:
  OAUTH-7523bis: I-D.draft-ietf-oauth-rfc7523bis-00
  OpenID.Core:
    author:
    - ins: N. Sakimura
      name: Nat Sakimura
    - ins: J. Bradley
      name: John Bradley
    - ins: M. Jones
      name: Michael B. Jones
    - ins: B. de Medeiros
      name: Breno de Medeiros
    - ins: C. Mortimore
      name: Chuck Mortimore
    date: December 2023
    target: https://openid.net/specs/openid-connect-core-1_0.html
    title: OpenID Connect Core 1.0 incorporating errata set 2
  OpenID.Discovery:
    author:
    - ins: N. Sakimura
      name: Nat Sakimura
    - ins: J. Bradley
      name: John Bradley
    - ins: M. Jones
      name: Michael B. Jones
    - ins: E. Jay
      name: Edmund Jay
    date: December 2023
    target: https://openid.net/specs/openid-connect-discovery-1_0.html
    title: OpenID Connect Discovery 1.0 incorporating errata set 2
  OpenID.CIBA:
    author:
    - ins: G. Fernandez
      name: Gonzalo Fernandez Rodriguez
    - ins: F. Walter
      name: Florian Walter
    - ins: A. Nennker
      name: Axel Nennker
    - ins: D. Tonge
      name: Dave Tonge
    - ins: B. Campbell
      name: Brian Campbell
    date: September 2021
    target: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
    title: OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0
  research.ust:
    author:
    - ins: P. Hosseyni
      name: Pedram Hosseyni
    - ins: R. Küsters
      name: Ralf Küsters
    - ins: T. Würtele
      name: Tim Würtele
    date: April 2025
    target: https://eprint.iacr.org/2025/629
    title: "Audience Injection Attacks: A New Class of Attacks on Web-Based Authorization and Authentication Standards"
  research.cuhk:
    author:
    - ins: K. Luo
      name: Kaixuan Luo
    - ins: X. Wang
      name: Xianbo Wang
    - ins: P. H. A. Fung
      name: Pui Ho Adonis Fung
    - ins: W. C. Lau
      name: Wing Cheong Lau
    - ins: J. Lecomte
      name: Julien Lecomte
    date: August 2025
    target: https://www.usenix.org/system/files/conference/usenixsecurity25/sec24winter-prepub-332-luo.pdf
    refcontent: "34th USENIX Security Symposium (USENIX Security 25)"
    title: "Universal Cross-app Attacks: Exploiting and Securing OAuth 2.0 in Integration Platforms"
  arXiv.1601.01229:
    author:
      - ins: D. Fett
        name: Daniel Fett
      - ins: R. Küsters
        name: Ralf Küsters
      - ins: G. Schmitz
        name: Guido Schmitz
    date: January 2016
    target: https://arxiv.org/abs/1601.01229/
    refcontent: "arXiv:1601.01229"
    seriesInfo:
      - name: DOI
      - value: 10.48550/arXiv.1601.01229
    title: "A Comprehensive Formal Security Analysis of OAuth 2.0"
  research.jcs_14:
    author:
      - ins: C. Bansal
        name: Chetan Bansal
      - ins: K. Bhargavan
        name: Karthikeyan Bhargavan
      - ins: A. Delignat-Lavaud
        name: Antoine Delignat-Lavaud
      - ins: S. Maffeis
        name: Sergio Maffeis
    date: April 2014
    target: https://www.doc.ic.ac.uk/~maffeis/papers/jcs14.pdf
    refcontent: "Journal of Computer Security, vol. 22, no. 4, pp. 601-657"
    seriesInfo:
      - name: DOI
      - value: 10.3233/JCS-140503
    title: "Discovering concrete attacks on website authorization by formal analysis"
  MCP-Spec:
    author:
      - name: Model Context Protocol Specification Authors
    date: March 2025
    target: https://modelcontextprotocol.io/specification/2025-03-26
    title: Model Context Protocol (MCP) Specification

--- abstract

This document updates the set of best current security practices for
OAuth 2.0 by extending the security advice given in RFC 6749, RFC
6750, and RFC 9700, to cover new threats that have been discovered
since the former documents have been published.


--- middle

# Introduction {#Introduction}

Since the publication of the first OAuth 2.0 Security Best Practices
document {{!RFC9700}}, new threats to OAuth 2.0 ecosystems have been
identified. This document therefore serves as an extension of the
original {{!RFC9700}} and is to be read in conjunction with it.

Like {{!RFC9700}} before, this document provides important security
recommendations and it is RECOMMENDED that implementers upgrade their
implementations and ecosystems as soon as feasible.

## Structure

TODO explain the document structure and how it "fits" with {{!RFC9700}}


## Conventions and Terminology

{::boilerplate bcp14-tagged}

This specification uses the terms "access token", "authorization
endpoint", "authorization grant", "authorization server", "client",
"client identifier" (client ID), "protected resource", "refresh
token", "resource owner", "resource server", and "token endpoint"
defined by OAuth 2.0 {{!RFC6749}}.

[^terminology-update]{: source="Tim W."}

[^terminology-update]: Make sure to update this list once the
    technical sections below are completed.

# Attacks and Mitigations {#AttacksMitigations}

TODO section intro, mention that we do not repeat {{!RFC9700}} stuff
here

## Audience Injection Attacks {#AudienceInjection}

When using signature-based client authentication methods such as
`private_key_jwt` as defined in {{OpenID.Core}} or signed JWTs as
defined in {{!RFC7521}} and {{!RFC7523}}, a malicious authorization
server may be able to obtain and use a client's authentication
credential, enabling them to impersonate a client towards another
honest authorization server.

### Attack Description

The descriptions here follow {{research.ust}}, where additional details
of the attack are laid out.  Audience injection attacks require a client
to interact with at least two authorization servers, one of which is
malicious, and to authenticate to both with a signature-based
authentication method using the same key pair.  The following
description uses the `jwt-bearer` client authentication from
{{!RFC7523}}, see {{AudienceInjectionAuthNMethods}} for other affected
client authentication methods.  Furthermore, the client needs to be
willing to authenticate at an endpoint other than the token endpoint at
the attacker authorization server (see {{AudienceInjectionEndpoints}}).

#### Core Attack Steps

In the following, let H-AS be an honest authorization server and let
A-AS be an attacker-controlled authorization server.

Assume that the authorization servers publish the following URIs for
their token endpoints, for example via mechanisms such as authorization
server metadata {{?RFC8414}} or OpenID Discovery {{OpenID.Discovery}}.
The exact publication mechanism is not relevant, as audience injection
attacks are also possible on clients with manually configured
authorization server metadata.

Excerpt from H-AS' metadata:

~~~ javascript
"issuer": "https://honest.com",
"token_endpoint": "https://honest.com/token",
...
~~~

Excerpt from A-AS' metadata:

~~~ javascript
"issuer": "https://attacker.com",
"token_endpoint": "https://honest.com/token",
...
~~~

Therefore, the attacker authorization server claims to use the honest
authorization server's token endpoint. Note that the attacker
authorization server does not control this endpoint. The attack then
commences as follows:

1. Client registers at H-AS, and gets assigned a client ID `cid`.
2. Client registers at A-AS, and gets assigned the same client ID
   `cid`. Note that the client ID is not a secret ({{Section 2.2 of
   !RFC6749}}).

Now, whenever the client creates a client assertion for authentication
to A-AS, the assertion consists of a JSON Web Token (JWT) that is signed
by the client and contains, among others, the following claims:

~~~ json
"iss": "cid",
"sub": "cid",
"aud": "https://honest.com/token"
~~~

Due to the malicious use of H-AS' token endpoint in A-AS'
authorization server metadata, the `aud` claim contains H-AS' token
endpoint.  Recall that both A-AS and H-AS registered the client with
client ID `cid`, and that the client uses the same key pair for
authentication at both authorization servers.  Hence, this client
assertion is a valid authentication credential for the client at
H-AS.

The use of the token endpoint to identify the authorization server as a
client assertion's audience even for client assertions that are not sent
to the token endpoint is encouraged, or at least allowed by many
standards, including {{RFC7521}}, {{RFC7522}}, {{RFC7523}}, {{RFC9126}},
{{OpenID.Core}}, {{OpenID.CIBA}}, and all standards referencing the IANA
registry for OAuth Token Endpoint Authentication Methods for available
client authentication methods.

As described in {{research.ust}}, the attacker can then utilize the
obtained client authentication assertion to impersonate the client and,
for example, obtain access tokens.

#### Endpoints Requiring Client Authentication {#AudienceInjectionEndpoints}

As mentioned above, the attack is only possible if the client
authenticates to an endpoint other than the token endpoint at A-AS.
This is because if the client sends a token request to A-AS, it will use
A-AS' token endpoint as published by A-AS and hence, send the token
request to H-AS, i.e., the attacker cannot obtain the client assertion.

As detailed in {{research.ust}}, the attack is confirmed to be possible
if the client authenticates with such client assertions at the following
endpoints of A-AS:

- Pushed Authorization Endpoint (see {{?RFC9126}})
- Token Revocation Endpoint (see {{?RFC7009}})
- CIBA Backchannel Authentication Endpoint (see {{OpenID.CIBA}})
- Device Authorization Endpoint (see {{?RFC8628}})

Note that this list of examples is not exhaustive. Hence, any client
that might authenticate at any endpoint other than the token endpoint
SHOULD employ countermeasures as described in
{{AudienceInjectionCountermeasures}}.

#### Affected Client Authentication Methods {#AudienceInjectionAuthNMethods}

The same attacks are possible for the `private_key_jwt` client
authentication method defined in {{OpenID.Core}}, as well as
instantiations of client authentication assertions defined in
{{!RFC7521}}, including the SAML assertions defined in {{?RFC7522}}.

Furthermore, a similar attack is possible for `jwt-bearer` authorization
grants as defined in {{Section 2.1 of !RFC7523}}, albeit under
additional assumptions (see {{research.ust}} for details).

### Countermeasures {#AudienceInjectionCountermeasures}

At its core, audience injection attacks exploit the fact that, from the
client's point of view, an authorization server's token endpoint is a
mostly opaque value and does not uniquely identify an authorization
server.  Therefore, an attacker authorization server may claim any URI
as its token endpoint, including, for example, an honest authorization
server's issuer identifier. Hence, as long as a client uses the token
endpoint as an audience value when authenticating to the attacker
authorization server, audience injection attacks are possible.
Therefore, audience injection attacks need to be prevented by the
client.

Note that the following countermeasures mandate the use of single
audience value (as opposed to multiple audiences in array). This is because {{Section 4.1.3
of ?RFC7519}} allows the receiver of an audience-restricted JWT to
accept the JWT even if the receiver identifies with only one of the
values in such an array.

Clients that interact with more than one authorization server and
authenticate with signature-based client authentication methods MUST
employ one of the following countermeasures, unless audience injection
attacks are mitigated by other means, such as using fresh key material
for each authorization server.

Note that the countermeasures described in
{{AudienceInjectionCountermeasuresASissuer}} and
{{AudienceInjectionCountermeasuresTargetEP}} do not imply any normative
changes to the authorization server: {{Section 4.1.3 of ?RFC7519}}
requires the authorization server to only accept a JWT if the
authorization server can identify itself with (at least one of the
elements in) the JWT's audience value. Authentication JWTs produced by a
client implementing one of these countermeasures meet this condition.
Of course, an authorization server MAY still decide to only accept its
issuer identifier ({{AudienceInjectionCountermeasuresASissuer}}) or the
endpoint that received the JWT
({{AudienceInjectionCountermeasuresTargetEP}}) as an audience value, for
example, to force its clients to adopt the respective countermeasure.

#### Authorization Server Issuer Identifier {#AudienceInjectionCountermeasuresASissuer}

Clients MUST use the authorization server's issuer identifier as defined
in {{!RFC8414}}/{{OpenID.Discovery}} as the sole audience value in
client assertions. Clients MUST retrieve and validate this value as
described in {{Section 3.3 of !RFC8414}}/Section 4.3 of
{{OpenID.Discovery}}.

For `jwt-bearer` client assertions as defined by {{RFC7523}}, this
mechanism is also described in {{OAUTH-7523bis}}.

Note that "issuer identifier" here does not refer to the term "issuer"
as defined in {{Section 4.4 of RFC9700}}, but to the issuer identifier
defined in {{!RFC8414}} and {{OpenID.Discovery}}. In particular, the
issuer identifier is not just "an abstract identifier for the
combination the authorization endpoint and token endpoint".


#### Exact Target Endpoint URI {#AudienceInjectionCountermeasuresTargetEP}

Clients MUST use the exact endpoint URI to which a client assertion is
sent as that client assertion's sole audience value.

This countermeasure can be used for authorization servers that do not
use authorization server metadata {{!RFC8414}} or OpenID Discovery
{{OpenID.Discovery}}.


## Updates to Mix-Up Attacks {#MixUpUpdate}
Mix-up attacks can occur in scenarios where an OAuth client interacts with two or more authorization servers and at least one authorization server is under the control of the attacker.

This section extends the mix-up attack analysis in {{Section 4.4 of !RFC9700}}. It introduces additional attack variants that can occur when clients use distinct redirection URIs for each authorization server and clarifies the applicability of countermeasures to certain attack variants.

### Updates to "Per-AS Redirect URIs" Mix-Up Variant {#PerASUpdate}

The main mix-up attack variant described in the initial paragraphs of {{Section 4.4.1 of !RFC9700}} specifies, as one of its preconditions, that "the client stores the authorization server chosen by the user in a session bound to the user's browser and uses the same redirection URI for each authorization server".

If the client instead uses a distinct redirection URI for each authorization server (i.e., Per-AS Redirect URIs), three subvariants of mix-up attacks remain possible. The following replaces the description of the "Per-AS Redirect URIs" mix-up variant in {{Section 4.4.1 of !RFC9700}}, with subvariants 1 and 2 newly introduced in this document:


Per-AS Redirect URIs: There are three subvariants of mix-up attacks when the client uses distinct redirection URIs for each authorization server.

* Subvariant 1: If the client uses different redirection URIs for different authorization servers but treats them as the same URI (i.e., the client continues to store the authorization server chosen by the user in a session and does not use the redirection URI to differentiate authorization servers at the redirection endpoint), a slight variant of the main mix-up attack variant would still work (see Footnote 7 of {{arXiv.1601.01229}} and Section 4.2.1 of {{research.cuhk}}). An attacker can achieve this by replacing the redirection URI as well as the client ID at A-AS with those at H-AS in the authorization request, when redirecting the browser to the authorization endpoint of H-AS.

{:style="empty"}
* Specifically, assuming that the client issues the redirection URI `https://client.com/9XpLmK2qR/cb` for H-AS and `https://client.com/4FvBn8TzY/cb` for A-AS, an attack is feasible with the following modifications to Step 2 and Step 3:
* 2\. The client stores in the user's session that the user selected "A-AS" and redirects the user to A-AS's authorization endpoint with a Location header containing the URL `https://attacker.example/authorize?response_type=code&client_id=666RVZJTA`
  `&redirect_uri=https%3A%2F%2Fclient.com%2F4FvBn8TzY%2Fcb`.
* 3\. When the user's browser navigates to the attacker's authorization endpoint, the attacker immediately redirects the browser to the authorization endpoint of H-AS. In the authorization request, the attacker replaces the client ID of the client at A-AS with the client's ID at H-AS, and replaces the redirection URI of A-AS with the redirection URI of H-AS. Therefore, the browser receives a redirection (`303 See Other`) with a Location header pointing to `https://honest.as.example/authorize?response_type=code&client_id=7ZGZldHQ`
  `&redirect_uri=https%3A%2F%2Fclient.com%2F9XpLmK2qR%2Fcb`.

{:style="symbols"}
* Subvariant 2: If clients use different redirection URIs for different authorization servers, and clients do not store the selected authorization server in the user's session, attackers can mount an attack called "Naïve RP Session Integrity Attack". Note that unlike other mix-up variants, the goal of this attack is not to obtain an authorization code or access token, but to force the client to use an attacker's authorization code or access token for H-AS. See Section 3.4 of {{arXiv.1601.01229}} and Section 4.2.2 of {{research.cuhk}} for details.
* Subvariant 3: If clients use different redirection URIs for different authorization servers, clients do not store the selected authorization server in the user's session, and authorization servers do not check the redirection URIs properly (see {{Section 4.1 of !RFC9700}}), attackers can mount an attack called "Cross Social-Network Request Forgery". These attacks have been observed in practice. Refer to {{research.jcs_14}} for details.

[^standalonesection]{: source="Kaixuan L."}

[^standalonesection]: Currently I lump "Naïve RP Session Integrity Attack"/CORF under mix-up variants, rather than as a standalone (sub)section, since the general attack scenario and defense are the same as mix-up/COAT. That said, shall we expand its attack description to elaborate on the attack steps?

### Clarifications on Countermeasures for Mix-Up Variants {#CountermeasureUpdate}

According to the countermeasures specified in {{Section 4.4.2 of !RFC9700}} (referred to hereafter as "existing mix-up defenses"), both defenses require the client to store and compare the issuer of the authorization server. Specifically, the issuer is defined in the second paragraph of {{Section 4.4.2 of !RFC9700}} as follows:

{:style="empty"}
* The issuer serves ... as an abstract identifier for the combination of the authorization endpoint and token endpoint that are to be used in the flow. If an issuer identifier is not available ..., a different unique identifier for this tuple or the tuple itself can be used instead.

Existing mix-up defenses are sufficient to protect against most attack variants, with a few specific cases requiring clarification:

* For the mix-up attack variant in "Implicit Grant", since the flow does not involve a token endpoint, a unique identifier for the authorization endpoint URL MAY be used as the equivalent of issuer if an issuer identifier is not available. Then, clients MUST apply existing mix-up defenses.

* For all three subvariants of the "Per-AS Redirect URIs" attack variant ({{PerASUpdate}}), clients MUST follow existing mix-up defenses to defend against mix-up attacks. Clients MAY choose to reuse the per-AS redirection URI already configured in their deployments to satisfy the "distinct redirection URI for each issuer" requirement when implementing the "Mix-Up Defense via Distinct Redirect URIs" defense ({{Section 4.4.2.2 of !RFC9700}}). For subvariant 3 ("Cross Social-Network Request Forgery"), the existing mix-up defenses alone are not sufficient. In addition, authorization servers MUST enforce exact redirection URI matching, as specified in {{Section 4.1.3 of !RFC9700}}.

Note that when the issuer is not unique to a client (i.e., when a client can interact with multiple configurations of the same authorization server), the security considerations go beyond the scope of mix-up attacks and are discussed further in {{OpenEcosystem}}.


## Attacks in Open Ecosystems {#OpenEcosystem}

This section describes the OAuth use case and associated attacks in open ecosystems, along with practical countermeasures tailored to such environments.

### OAuth in Open Ecosystems {#ApplicationScenario}

In traditional OAuth deployments, a client registers with an authorization server to access protected resources hosted by a resource server.
The means through which the client registers with an authorization server typically involve the client developer manually registering the client at the authorization server's website, or by using Dynamic Client Registration {{?RFC7591}}.
The client may access different resources from distinct resource servers, thereby requiring registration with multiple authorization servers.
The choice of what resources to access (and thus which authorization and resource servers to integrate) is at the discretion of the client (or client developer).

This document discusses OAuth in "open ecosystems", where the protected resources available to a client are configured beyond the discretion of the client or client developers. This can be the case, for example, if an end-user can specify arbitrary resource servers and associated authorization servers to interact with at runtime (e.g., in the Model Context Protocol {{MCP-Spec}}), or if the client offers an open marketplace or registry with such configurations published by external developers at development time (e.g., in integration platforms {{research.cuhk}}).

This document defines a "client configuration" as a bundle of configuration elements that enable a client in open ecosystems to access an OAuth 2.0 protected resource. A client configuration typically includes:

* Authorization Server configuration. Clients may employ a manual approach, where end-users or external developers enter the necessary fields (i.e., endpoint URLs of the authorization server) at the client's website, or support fetching information about the authorization server via Authorization Server Metadata {{?RFC8414}}.
* Client Registration configuration at the authorization server. Clients may employ a manual approach, where end-users or external developers enter the necessary fields (i.e., client identifier and client credentials) at the client's website, or support fetching information about the client registration via Dynamic Client Registration {{?RFC7591}}.
* Protected Resource configuration. Clients may employ a manual approach, where end-users or external developers enter the necessary fields (i.e., endpoint URLs of the resource server) at the client's website, or support fetching information about the protected resource via Protected Resource Metadata {{?RFC9728}}. End-users or external developers may further specify when and how the protected resources shall be fetched and processed by the clients.

The integration pattern in open ecosystems expands the use of OAuth in dynamic scenarios, creating new challenges with respect to functionality and security beyond the scope of {{!RFC9700}}.

### Attack Scenario {#AttackScenario}

With the new integration model, OAuth in open ecosystems introduces two notable implications:

* Lower barrier for malicious infiltration: Since the responsibility of integrating client configurations is shifted to end-users or external developers, it becomes easier to introduce malicious client configurations, including attacker-controlled authorization servers or resource servers.
* New requirements for handling shared issuers: Clients must support potentially issuer-sharing client configurations to fulfill functional needs, which in turn introduces new security requirements (explained below).

In traditional OAuth deployments, it is implicitly assumed that each authorization server has only one client configuration at a client. Under this assumption, the issuer serves as a unique identifier for the client. This has led to the common practice of clients tracking "the authorization server chosen by the user" during OAuth flows, as well as the adoption of existing mix-up defenses ({{Section 4.4.2 of !RFC9700}}), all of which are based on the issuer concept that uniquely identifies each authorization server.

However, in open ecosystems, such assumption no longer hold. Authorization servers and resource servers are dynamically configurable at the client. The new integration pattern in open ecosystems does not, and fundamentally cannot, restrict the use of the same authorization server across multiple client configurations.

This is because clients are legitimately allowed to integrate various functionalities that access different resources or process the same resources differently, while relying on the same authorization server. As a result, an attacker may integrate either an authorization server under their control ({{MixUpReloaded}}), or an honest authorization server -- including one that is already integrated under a different client configuration at the same client ({{ConfigConfusion}}).

Note that this section limits the scope of attacks to the reuse of registered clients, and considers phishing threats involving the open registration of new clients as out of scope (which can be mitigated by existing mechanisms such as vetting during manual registration, or via initial access tokens as defined in {{Section 1.2 of ?RFC7591}}).

### Mix-Up Attacks Reloaded {#MixUpReloaded}

This section provides a tailored attack description and alternative countermeasure for mix-up attacks in open ecosystems. The descriptions here follow {{research.cuhk}}, where additional details are laid out.

#### Attack Description {#ReloadedDescription}

{{Section 4.4 of !RFC9700}} exemplifies scenarios in which an attacker-controlled authorization server may be introduced:

{:style="empty"}
* This can be the case, for example, if the attacker uses dynamic registration to register the client at their own authorization server, or if an authorization server becomes compromised.

OAuth deployments in open ecosystems extend the above scenarios: an end-user or external developer can introduce an attacker-controlled authorization server by integrating a new client configuration at the client.

Furthermore, multiple client configurations may use the same authorization server (i.e., share the same issuer).
To manage such scenarios, the client should treat each client configuration independently, typically by keeping track of the client configuration chosen by the user during the OAuth flow. For example, the client may store a unique identifier for each client configuration (rather than for each authorization server) in the user's session, or assign a distinct redirection URI to each client configuration.
This enables the client to distinguish between client configurations, retrieve the correct client registration information for access token requests, and access the intended protected resources.

Attackers can exploit this setup to mount a mix-up attack, using a malicious authorization server from an attacker-controlled client configuration to target the honest authorization server from an honest client configuration. The attack steps are similar to the main mix-up attack variant described in the initial paragraphs of {{Section 4.4.1 of !RFC9700}}. For details on this attack vector, see "Cross-app OAuth Account Takeover" (COAT) and "Cross-app OAuth Request Forgery" (CORF) in Section 4.2 of {{research.cuhk}}.


#### Countermeasures {#ReloadedCountermeasure}

At its core, a client in open ecosystems may integrate multiple configurations of the same authorization server, and therefore the issuer may not be unique to the client. While the existing mix-up defenses in {{Section 4.4.2 of !RFC9700}} are sufficient, a variant of the "Mix-Up Defense via Distinct Redirect URIs" defense described in {{Section 4.4.2.2 of !RFC9700}} MAY be deployed instead for practical reasons:

{:style="empty"}
* To apply this defense, clients MUST use a distinct redirection URI for each client configuration they interact with. Clients MUST check that the authorization response was received from the correct client configuration by comparing the distinct redirection URI for the client configuration to the URI where the authorization response was received on. If there is a mismatch, the client MUST abort the flow.

[^discussion]{: source="Kaixuan L."}

[^discussion]: We currently mark this variant defense as a `MAY`/`OPTIONAL` to apply; if implemented, implementers `MUST` adhere to the requirements specified in the defense. This is open for discussion.

To maximize compatibility, this countermeasure imposes no new requirements on authorization servers compliant with the original OAuth 2.0 specification {{!RFC6749}}. This is essential for securing open ecosystems where clients may be integrated with numerous client configurations, and many authorization servers may not support the "Mix-Up Defense via Issuer Identification" defense described in {{Section 4.4.2.1 of !RFC9700}} (e.g., returning the issuer identifier via an `iss` parameter in the authorization response {{?RFC9207}}).

To ease the development burden, compared to the "Mix-Up Defense via Distinct Redirect URIs" defense outlined in {{Section 4.4.2.2 of !RFC9700}}, this countermeasure does not require clients to manage issuers exclusively for mix-up defense. Instead, it relies on existing isolation boundaries that already serve the functional need of differentiating client configurations.

Note that this countermeasure is not intended to redefine the concept of an issuer (or issuer identifier) from an authorization server-specific identifier to one tied to client configurations. Nor does it invalidate the existing countermeasures described in {{Section 4.4.2 of !RFC9700}} and clarified in {{CountermeasureUpdate}}, which remain sufficient to mitigate mix-up attacks in open ecosystems. Rather, this countermeasure MAY serve as an alternative defense.

### Client Configuration Confusion Attack {#ConfigConfusion}

[^alternativename]{: source="Kaixuan L."}

[^alternativename]: Alternative Names: RS/AS-RS Mix-up/Confusion. Any better ideas?

When client authentication is not required such as in the implicit grant or for a public client, or when signature-based client authentication methods such as `private_key_jwt` (as defined in {{OpenID.Core}}) or signed JWTs (as defined in {{!RFC7521}} and {{!RFC7523}}) are used, a malicious resource server may be able to obtain an access token issued by an honest authorization server.
This is achieved by registering an honest authorization server at the client under a malicious client configuration, pairing it with an attacker-controlled resource server, thus tricking the client into sending its access tokens to the attacker instead of using them at the honest resource server.

Unlike mix-up attacks or audience injection attacks, client configuration confusion attacks do not involve a malicious authorization server, but rather an honest one used in a malicious client configuration.

#### Attack Description {#ConfigConfusionAttack}

Client configuration confusion attacks are feasible if a client satisfies the following preconditions:

1. The client has at least two client configurations, one of which is configured by an attacker. The client allows for the two configurations to use the same authorization server (i.e., issuer-sharing client configurations) but different resource servers.
2. The client stores the client configuration chosen by the user in a session bound to the user's browser and assigns the same redirection URI for at least the issuer-sharing, if not all, client configurations.
3. The client uses the same client ID across the issuer-sharing client configurations.
4. Regarding client authentication, one of the following applies:

* The client authenticates to the authorization server in both client configurations with a signature-based authentication method (e.g., the `jwt-bearer` client authentication from {{!RFC7523}}) using the same key pair.
* The client interacts with the authorization server in both client configurations without requiring client authentication (i.e., using the implicit grant, or as a public client).

For brevity of presentation, in the following, let H-AS, H-RS, and H-Config denote an honest authorization server, resource server, and client configuration, respectively. Let A-AS, A-RS, and A-Config denote an attacker-controlled authorization server, resource server, and client configuration, respectively.

##### Core Attack Steps {#ConfusionCoreSteps}

In the following, it is further assumed that the client is registered with H-AS for both client configurations. The client is configured to use A-RS for A-Config and H-RS for H-Config.

Attack on the authorization code grant:

1. The user selects to start the grant using A-Config (e.g., by clicking on a button on the client's website).
2. The client stores in the user's session that the user selected "A-Config" and redirects the user to H-AS's authorization endpoint.
3. The user authorizes the client to access their resources at H-AS. Having validated that the client ID and redirection URI match the ones assigned for H-Config, H-AS issues a code and sends it (via the browser) back to the client.
4. The client redeems the code issued by H-AS at H-AS's token endpoint. To authenticate with H-AS, the client creates a client assertion signed by itself. Recall that both A-Config and H-Config registered the client with H-AS under the same client ID, and that the client uses the same key pair for authentication at H-AS. Hence, this client assertion, if required, would be a valid authentication credential for the client at H-AS. Note that generating and validating client assertions in this step is optional for public clients.
5. Since the client stores "A-Config" in the user's session, it sends the access token to A-RS. The attacker therefore obtains the user's access token issued by H-AS.

Variant in Implicit Grant:
In the implicit grant, H-AS issues an access token instead of the code in Step 3. Step 4 is omitted. The rest of the attack proceeds as above.

##### Notice on Sharing Client IDs

For the attack to work, A-Config and H-Config need to share the same client ID in client registration (precondition 3 in {{ConfigConfusionAttack}}). This can be the case, for example, if an end-user or external developer can control the client ID used in A-Config during manual registration, or if the client uses dynamic registration to get assigned the same client ID as in H-Config, as detailed below.

When the client is designed to perform dynamic client registration once per client configuration, A-Config and H-Config could feasibly share the same client ID.
Unlike the situation in {{AudienceInjection}}, since A-Config uses H-AS instead of A-AS, the attacker cannot directly control which client ID the authorization server assigns to A-Config.
However, according to the description of client ID returned in Client Information Response ({{Section 3.2.1 of ?RFC7591}}):

client_id
: OAuth 2.0 client identifier string.  It SHOULD NOT be currently valid for any other registered client, though an authorization server MAY issue the same client identifier to multiple instances of a registered client at its discretion.

The second half of the last sentence explicitly allows a client to obtain a client ID of the same value across multiple client registrations, as long as the client is not considered to be unrelated registered clients by the authorization server, but instances of the same registered client.

This behavior is intended for registering different "client instances", i.e., different deployed instances of the same piece of client software (see {{Section 1.2 of ?RFC7591}}). However, the authorization server cannot distinguish between this case and a client registering multiple times for different client configurations.

Therefore, a client interacting with A-Config and H-Config could feasibly obtain the same client ID, when the client, based on A-Config, initiates dynamic registration at H-AS. The authorization server, recognizing the two client registration requests as originating from the same client (e.g., indicated by the identical software identifier or software statement provided by the client), is likely to return the same client ID according to {{Section A.4.2 of ?RFC7591}}:

{:style="empty"}
* Particular authorization servers might choose, for instance, to maintain a mapping between software statement values and client identifier values, and return the same client identifier value for all registration requests for a particular piece of software.


#### Countermeasures {#ConfigConfusionCounter}

At its core, client configuration confusion attacks exploit the fact that, an attacker-controlled client configuration can reuse the registered client at the honest authorization server under an honest client configuration.

Clients in open ecosystems that interact with more than one client configuration and support authorization servers that either use signature-based client authentication methods or do not require client authentication MUST employ the following countermeasure, unless client configuration confusion attacks are mitigated by other means, such as using fresh key material for each authorization server employing signature-based client authentication and disallowing any authorization server that does not require client authentication.

Clients MUST issue a distinct redirection URI for each client configuration they interact with, both during client registration and in OAuth flows. This ensures that the redirection URI for the attacker-controlled client configuration will fail the exact redirection URI match (required by {{Section 4.1.3 of !RFC9700}}) at the honest authorization server, since the redirection URI at the honest client configuration is the only redirection URI registered for the client identifier at the honest authorization server.

When dynamic client registration is supported, clients SHOULD also specify a different software identifier (`software_id`) in client registration requests for each client configuration. This precents client registration requests from being rejected by the authorization server when different redirection URIs are used, if the authorization server follows the excerpt of {{Section 5 of ?RFC7591}} below:

{:style="empty"}
* An authorization server could also refuse registration requests from a known software identifier that is requesting different redirection URIs or a different client URI.

[^fordiscussion]{: source="Kaixuan L."}

[^fordiscussion]: This imposes a normative change to the use of `software_id` in RFC7591, where "the 'software_id' `SHOULD` remain the same for all instances of the client software." Here we are basically requiring a client software instance to have different software ids for different client configurations. Is there a better solution?

This countermeasure can be considered an actionable approach to mitigating the "Counterfeit Resource Server" threat (see "Access Token Phishing by Counterfeit Resource Server" in {{Section 4.9.1 of !RFC9700}}) within the context of open ecosystems.

# Security Considerations {#Security}

Security considerations are described in {{AttacksMitigations}}.


# IANA Considerations {#IANA}

This document has no IANA actions.


--- back

# Acknowledgments {#Acknowledgements}
{:numbered="false"}

We would like to thank
Adonis Fung,
Kaixuan Luo,
[^acksAddNames]{: source="Tim W."}
Daniel Fett,
Wing Cheong Lau,
Julien Lecomte,
Aaron Parecki,
Guido Schmitz,
Xianbo Wang,
[^acksAddNamesLuo]{: source="Kaixuan L."}

[^acksAddNames]: TODO add names, sort by last name.

[^acksAddNamesLuo]: Added by Kaixuan.

for their valuable feedback and contributions to this document.
