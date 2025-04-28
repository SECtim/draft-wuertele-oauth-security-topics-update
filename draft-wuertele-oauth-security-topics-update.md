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
Adonis Fung,
Kaixuan Luo,
[^acksAddNames]{: source="Tim W."}

[^acksAddNames]: TODO add names, sort by last name.
for their valuable feedback and contributions to this document.
