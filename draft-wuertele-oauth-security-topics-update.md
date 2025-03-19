---
title: "OAuth 2.0 Security Best Current Practice"
abbrev: "OAuth 2.0 Security BCP"
category: bcp
seriesno: 240
docname: draft-wuertele-oauth-security-topics-update-latest
updates: 6749, 6750, 9700

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

normative:

informative:
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

[^desc-len]{: source="Tim W."}

[^desc-len]: In its current form, the attack description is probably way
    too long and complex. Maybe we can make it more accessible by
    introducing some more structure. E.g., "Preconditions", "Attack
    Sequence"(?), "Impact", "Variants".

The descriptions here follow [TODO paper], where additional details of
the attack are laid out.  Audience injection attacks require a client
to interact with at least two authorization servers, one of which is
malicious, and to authenticate to both with a signature-based
authentication method using the same key pair.  The following
description uses the `jwt-bearer` client authentication from
{{!RFC7523}}, see below for further variants.  Furthermore, the client
needs to be willing to authenticate at an endpoint other than the
token endpoint at the attacker authorization server.  The following
description uses the pushed authorization request endpoint defined by
{{?RFC9126}}, see below for further variants.

[^oid-fed-ex]{: source="Tim W."}

[^oid-fed-ex]: Mention OID Federation and FAPI 2.0 here as examples of
    profiles that force clients to do that?

Assume that the authorization servers publish the following URIs for
their authorization, token, and pushed authorization request
endpoints, for example via mechanisms such as authorization server
metadata {{?RFC8414}} or OpenID Discovery {{OpenID.Discovery}}.
However, audience injection attacks are also possible on clients with
manually configured authorization server metadata.

Excerpt from H-AS' metadata:

~~~ javascript
"issuer": "https://honest.com",
"authorization_endpoint": "https://honest.com/authorize",
"token_endpoint": "https://honest.com/token",
"pushed_authorization_request_endpoint": "https://honest.com/par",
...
~~~

Excerpt from A-AS' metadata:

~~~ javascript
"issuer": "https://attacker.com",
"authorization_endpoint": "https://attacker.com/authorize",
"token_endpoint": "https://honest.com/token",
"pushed_authorization_request_endpoint": "https://attacker.com/par",
...
~~~

I.e., the attacker authorization server claims to use the honest
authorization server's token endpoint.  The attack now commences as
follows:

1. Client registers at H-AS, and gets assigned a client ID `cid`.
2. Client registers at A-AS, and gets assigned the same client ID
   `cid`. Note that the client ID is not a secret ({{Section 2.2 of
   !RFC6749}}).
3. Client starts an authorization code grant, e.g., triggered by the
   attacker as a user of the client, with A-AS by sending a pushed
   authorization request to A-AS' pushed authorization request
   endpoint.

Part of that pushed authorization request is a `client_assertion` that
authenticates the client.  This client assertion consists of a JSON
Web Token (JWT) that is signed by the client and contains, among
others, the following claims:

~~~ json
"iss": "cid",
"sub": "cid",
"aud": "https://honest.com/token"
~~~

The client issued this client assertion to authenticate at A-AS, but
due to the malicious use of H-AS' token endpoint in A-AS'
authorization server metadata, the `aud` claim contains H-AS' token
endpoint.  Recall that both A-AS and H-AS registered the client with
client ID `cid`, and that the client uses the same key pair for
authentication at both authorization servers.  Hence, this client
assertion - that the client just sent to A-AS' pushed authorization
endpoint - is also a valid authentication credential for the client at
H-AS.  The attacker can therefore use the client assertion to
impersonate the client at H-AS, for example, in a client credentials
grant.

[^impers-ex]{: source="Tim W."}

[^impers-ex]: Omit concrete examples here. Just say that the attacker
    can impersonate the client and may obtain access tokens, point to
    paper for details.

TODO variants


### Countermeasures

TODO

## TODO Title - "Mix-up reloaded" content

TODO

# Security Considerations {#Security}

Security considerations are described in {{AttacksMitigations}}.


# IANA Considerations {#IANA}

This document has no IANA actions.


--- back

# Acknowledgments {#Acknowledgements}
{:numbered="false"}

We would like to thank
Kaixuan Luo,
TODO add names, sort by last name
for their valuable feedback and contributions to this document.
