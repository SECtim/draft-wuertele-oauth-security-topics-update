---
title: "Updates to OAuth 2.0 Security Best Current Practice"
abbrev: "Updates to OAuth 2.0 Security BCP"
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
  CDFS: I-D.draft-ietf-oauth-cross-device-security-12
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
    target: https://www.usenix.org/system/files/usenixsecurity25-luo-kaixuan.pdf
    refcontent: "34th USENIX Security Symposium (USENIX Security 25)"
    title: "Universal Cross-app Attacks: Exploiting and Securing OAuth 2.0 in Integration Platforms"
  research.cuhk2:
    author:
    - ins: K. Luo
      name: Kaixuan Luo
    - ins: X. Wang
      name: Xianbo Wang
    - ins: A. Fung
      name: Adonis Fung
    - ins: J. Lecomte
      name: Julien Lecomte
    - ins: W. C. Lau
      name: Wing Cheong Lau
    date: August 2024
    target: https://www.blackhat.com/us-24/briefings/schedule/#one-hack-to-rule-them-all-pervasive-account-takeovers-in-integration-platforms-for-workflow-automation-virtual-voice-assistant-iot-38-llm-services-38994
    refcontent: "Black Hat USA 2024"
    title: "One Hack to Rule Them All: Pervasive Account Takeovers in Integration Platforms for Workflow Automation, Virtual Voice Assistant, IoT, & LLM Services"
  research.cuhk3:
    author:
    - ins: K. Luo
      name: Kaixuan Luo
    - ins: X. Wang
      name: Xianbo Wang
    - ins: A. Fung
      name: Adonis Fung
    - ins: Y. Bi
      name: Yanxiang Bi
    - ins: W. C. Lau
      name: Wing Cheong Lau
    date: August 2025
    target: https://www.blackhat.com/us-25/briefings/schedule/index.html#back-to-the-future-hacking-and-securing-connection-based-oauth-architectures-in-agentic-ai-and-integration-platforms-44686
    refcontent: "Black Hat USA 2025"
    title: "Back to the Future: Hacking and Securing Connection-based OAuth Architectures in Agentic AI and Integration Platforms"
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
      - ins: Anthropic
        name: Anthropic PBC
    date: June 2025
    target: https://modelcontextprotocol.io/specification/2025-06-18
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

The remainder of this document is organized as follows: Section 2 is a detailed analysis of the threats and implementation issues that can be found in the wild (at the time of writing) along with a discussion of potential countermeasures.


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

This section gives a detailed description of new attacks on OAuth implementations, along with potential countermeasures. Attacks and mitigations already covered in {{!RFC9700}} are not listed here, except where clarifications or new recommendations are made.
Generally, the attacks in this section assume a scenario where a client can interact with multiple authorization servers.

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


## Cross-tool OAuth Account Takeover {#COAT}

It is increasingly common that a single OAuth client supports multiple tools, and each of which is mapped to an OAuth provider configuration (which includes at least the authorization server (AS) endpoints and client registration). A successful OAuth connection is established when the OAuth client obtains an access token for a tool based on its corresponding OAuth provider configuration. The tool MAY then use the access token to access the user's resource at an API or resource server (RS).

Multiple OAuth connections can be linked to some form of user's identity based on these common deployment scenarios:

- Platform Integrations: The OAuth connections made with different tools are linked to a platform's user account or session (e.g., represented by a platform's user identifier or a short-lived anonymous session). This is common where a user authorizes a platform (e.g., agentic AI service) to orchestrate multiple tools, of which some of them together with their OAuth providers can be contributed by the public.
- Multi-tenant OAuth-as-a-Service: In cases when the OAuth client is managed by a multi-tenant OAuth-as-a-Service provider, a successful OAuth connection are linked to a tenant's user identifier in addition to the tenant identifier. This is a generalization of the last deployment scenario, where a platform using this OAuth-as-a-Service is becoming a tenant. A tenant can usually choose some off-the-shelf tools and add their own with custom OAuth providers to support the tenant's service.

When controlled by an attacker, the open configurations of OAuth providers have posed a new threat to this centralized OAuth client design. If the client fails to properly identify, track, and isolate which proper OAuth connection context (representing a combination of OAuth provider, tool, and tenant) is in use during an authorization flow, an attacker can exploit this to mount two categories of attacks {{research.cuhk}}{{research.cuhk3}}.

- Cross-tool OAuth Account Takeover (COAT): an attacker uses a malicious tool to steal a victim's authorization code issued by a honest OAuth provider of a honest tool, and apply the authorization code injection attack (as defined in {{Section 4.4 of !RFC9700}}) using the attacker's identity. This results in a compromised OAuth connection between the attacker's platform identity and the victim's tool account. The impact is equivalent to an account takeover: the attacker can operate the honest tool using the victim's tool account (hijacked either under the same platform, or even cross-tenant that shares a vulnerable OAuth-as-a-Service).
- Cross-tool OAuth Request Forgery (CORF): an attacker forces a victim to connect with a tool with the attacker's tool account. This results in a compromised OAuth connection between the victim's platform identity and the attacker's tool account. The resulting impact is similar to login CSRF (as described in {{Section 4.4.1.8 of !RFC6819}}): the victim unintentionally interacts with an honest tool on behalf of the attacker, and so the victim's traces can be monitored by the attacker using the same account.

### Attack Description {#COATDescription}
Preconditions: It is assumed that

* the implicit or authorization code grant is used with multiple OAuth connection contexts, of which one combination is considered "honest" (H-Tool using H-AS) and one is operated by the attacker (A-Tool using A-AS), and
* the client stores the connection context chosen by the user in a session bound to the user's browser, and
* the client issues redirection URIs which do not depend on all variables in the connection context (e.g., AS, tool, tenant).

In the following, it is further assumed that the client is registered with H-AS (URI: `https://honest.as.example`, client ID: `7ZGZldHQ`) and with A-AS (URI: `https://attacker.example`, client ID: `666RVZJTA`). Assume that the client issues the redirection URI `https://client.com/honest-cb` for H-AS and `https://client.com/attack-cb` for A-AS. URLs shown in the following example are shortened for presentation to include only parameters relevant to the attack.

Attack on the authorization code grant:

1. A victim user selects to start the grant using A-AS of A-Tool (e.g., by initiating a tool use on an agentic AI service).
2. The client stores in the user's session that the user has selected such OAuth connection context and redirects the user to A-AS's authorization endpoint with a Location header containing the URL `https://attacker.example/authorize?response_type=code&client_id=666RVZJTA&state=[state]`
  `&redirect_uri=https%3A%2F%2Fclient.com%2Fattack-cb`.
3. When the user's browser navigates to the A-AS, the attacker immediately redirects the browser to the authorization endpoint of H-AS. In the authorization request, the attacker uses the honest authorization URL and replaces the state with the one freshly received. Therefore, the browser receives a redirection with a Location header pointing to `https://honest.as.example/authorize?response_type=code&client_id=7ZGZldHQ&state=[state]`
  `&redirect_uri=https%3A%2F%2Fclient.com%2Fhonest-cb`.
4. Due to implicit or prior approvals, the user might not be prompted for a re-authorization (re-consent). H-AS issues a code and sends it (via the browser) back with the state to the client.
5. Since the client still assumes that the code was issued by A-Tool, as stored in the user's session (with state verified), it will try to redeem the code at A-AS's token endpoint.
6. The attacker therefore obtains code and can either exchange the code for an access token (for public clients) or perform an authorization code injection attack as described in {{Section 4.5 of !RFC9700}}.

This Cross-tool OAuth Account Takeover (COAT) attack is a generalization of the Cross-app OAuth Account Takeover as defined in {{research.cuhk}} and the mix-up attack as defined in {{Section 4.5 of !RFC9700}}. This COAT exploits confusion between the OAuth connection context (i.e., a combination of OAuth provider, tool, tenant) of a centralized client rather than limited to confusion between two distinct authorization servers.

Variants:

   *  Implicit Grant: In the implicit grant, the attacker receives an access token instead of the code in Step 4.  The attacker's authorization server receives the access token when the client makes either a request to the A-AS userinfo endpoint (defined in {{OpenID.Core}}) or a request to the attacker's resource server (since the client believes it has completed the flow with A-AS).
   *  Cross-tool OAuth Request Forgery (CORF): If clients do not store the selected OAuth connection context in the user's session, but in the redirection URI instead, attackers can mount an attack called Cross-tool OAuth Request Forgery (CORF). Note that unlike other variants, the goal of this attack is not to obtain an authorization code or access token, but to force the client to use an attacker's authorization code or access token for H-AS. This was referred to as Naïve RP Session Integrity Attack when the OAuth connection context is limited to AS, and is detailed in Section 3.4 of {{arXiv.1601.01229}}.
   *  Cross Social-Network Request Forgery. If clients use different redirection URIs for different authorization servers, clients do not store the selected authorization server in the user's session, and authorization servers do not check the redirection URIs properly (see {{Section 4.1 of !RFC9700}}), attackers can mount an attack called "Cross Social-Network Request Forgery". These attacks have been observed in practice. Refer to {{research.jcs_14}} for details.
   *  OpenID Connect: Some variants can be used to attack OpenID Connect. In these attacks, the attacker misuses features of the OpenID Connect Discovery {{OpenID.Discovery}} mechanism or replays access tokens or ID Tokens to conduct a mix-up attack. The attacks are described in detail in Appendix A of [arXiv.1704.08539] and Section 6 of [arXiv.1508.04324v2] ("Malicious Endpoints Attacks").

### Countermeasures {#COATCountermeasure}

Unlike what expected in {{Section 4.4 of !RFC9700}}, an authorization server (or issuer) is no longer unique to a client. In modern deployment scenarios, the OAuth client interacts with multiple combinations of OAuth providers, tools and tenants. The client MUST use all variables in their OAuth connection context to form a unique connection context identifier. For instances,

- a platform's client allowing one OAuth provider configuration per tool, while multiple tools can relying on same AS, SHOULD include the tool identifier.
- in addition to the above, a platform's client allowing multiple OAuth providers for a tool SHOULD include identifiers that represent the tool and the OAuth provider.
- in addition to the above, an OAuth-as-a-Service managed client MUST include identifiers that represent the tenant, tool and OAuth provider.

The client MUST issue distinct redirection URI that incorporates this unique connection context identifier. When initiating an authorization request, the client MUST store this identifier in the user's session. When an authorization response was received on the redirection URI endpoint, clients MUST also check that the context identifier from the URI matches with the one in the distinct redirection URI. If there is a mismatch, the client MUST abort the flow.

## Session Fixation {#SessionFixation}
Session fixation attacks can occur when the client relies on an authorization session fixated through a URL, instead of the existing user-agent session, to identify the user at the redirection endpoint.
The authorization session alone is then used to determine the intended recipient of the access token at the client. Although it is derived from the user-agent session, the client may fail to validate the authorization session's binding to the user-agent session.
This can be the case, for example, if the `state` parameter is used to carry application state, or if a session identifier is introduced into the OAuth flow.

In a session fixation attack, the attacker (attacker (A1) in {{Section 3 of !RFC9700}}) attempts to trick a victim into completing an OAuth flow that the attacker initated at the client, thereby linking the resulting access token to the attacker's own session with the client. The goal is to associate the attacker's session at the client with the victim's resources or identity, thereby giving the attacker at least limited access to the victim's resources. This contrasts with Cross-Site Request Forgery (CSRF) attacks (see {{Section 4.7 of !RFC9700}}), which cause a victim to access the attacker's resources.


Note that this section focuses on the authorization code grant. For similar attacks in Cross-device OAuth flows, see {{Section 4 of CDFS}}.


### Attack Description {#FixationAttack}
The session fixation attack works as follows, with variants of the attack outlined below:

Preconditions: For this variant to work, it is assumed that the client uses `state` to carry the authorization session.

1. The attacker initiates OAuth and obtains an authorization request URL.
2. The attacker sends this authorization request URL to the victim; the URL contains the `state` parameter indicating the attacker's authorization session.
3. The victim visits the URL and authorizes the client to access their resources.
4. Upon receiving the request to the redirection endpoint, the client determines based on the authorization session that the attacker initiated the OAuth flow, thereby associating the attacker's session at the client with the victim's resources.
5. The attacker now gains access to the victim's resources.

Variant:

A variant of the attack can occur when the client employs other means to indicate the authorization session. For example, when a user chooses to start OAuth at the client, the client may first generate a request URL that includes a session ID parameter pointing to the client's website, before redirecting to the authorization endpoint.
The following non-normative example shows such a request, where the `auth_session_id` value is derived from the user-agent session:

    GET /oauth?auth_session_id=6064f11c-f73e-425b-b9b9-4a36088cdb2b HTTP/1.1
    Host: client.com


The following non-normative example shows the response, which redirects the browser to the authorization request while setting the authorization session in the browser:

    HTTP/1.1 303 See Other
    Location: https://as.example/authorize?
              response_type=code&client_id=K9dTpWzqL7&state=b1d8f043
              &redirect_uri=https%3A%2F%2Fclient.com%2Fcb
    Set-Cookie: auth_session_id=6064f11c-f73e-425b-b9b9-4a36088cdb2b


Under this variant, Step 1 and Step 2 work as follows:

1. The attacker initiates OAuth and obtains an initial request URL that will generate the authorization request URL.
2. The attacker sends this initial request URL to the victim; the custom parameter in the URL indicates the attacker's authorization session.
The remainder of the attack proceeds as described above.


### Discussion {#FixationDiscussion}

In traditional OAuth deployments for web applications, where a single origin (the client) and a single user-agent (the web browser) are involved, the session fixation vulnerability can be viewed as a failure to validate the binding of `state` to the user-agent session ({{Section 4.7.1 of !RFC9700}}), or as a failed attempt to retrofit the concept of an authorization session (ID) into OAuth. In such cases, the user-agent session is accessible to the client's redirection endpoint for validation, because they share the same origin (per the same-origin policy {{?RFC6454}}) or, more generally, the same domain (per the cookie standard {{?RFC6265}}).


In more complex OAuth deployments, the pattern of relying on a URL-fixated authorization session, rather than the original session at the user-agent, often stems from the user-agent session not being available to the client at the redirection endpoint:

* In Cross-origin OAuth deployments, the redirection endpoint is hosted at a different origin from where the client application's user-agent session exists.
* In Cross-user-agent OAuth deployments, native app clients that store tokens at their backend and follow {{!RFC8252}} to perform OAuth in an external user-agent (e.g., a browser) do not have access to the session of the original user-agent (i.e., the native app), when the authorization code is submitted at the redirection endpoint hosted by the native app's backend.
* In OAuth deployments where the application's user session and its OAuth client are handled by separate services of the same party (e.g., in a microservice architecture) or by different parties (e.g., in the business model of "OAuth-as-a-Service"), the client's redirection endpoint may be unable to interpret the application's user-agent session.

Session fixation attacks in these complex deployments have been observed in practice. Refer to {{research.cuhk2}} and {{research.cuhk3}} for details.

### Countermeasures {#FixationCountermeasures}

At its core, defending against session fixation requires ensuring that an OAuth flow initiated by one user cannot be completed by another user.

Note that PKCE {{?RFC7636}} does not mitigate the attack, because both the authorization request and the access token request are completed within the same OAuth flow by the same user (the victim).

The following countermeasure addresses the root cause:

The clients MUST validate the binding of authorization session (whether conveyed via `state` or session cookies) to the existing user-agent session, before proceeding with authorization code exchange.

* When the user-agent session is available to, and identifiable by, the client at the redirection endpoint (e.g., in same-origin, same-user-agent deployments), clients can perform the validation directly.
* In cross-origin deployments, this requires either relocating the redirection endpoint, or redirecting from the redirection endpoint, to a location where the user-agent session is available, and then validate the binding.
* In cross-user-agent deployments, this requires either relocating, or redirecting from, the redirection endpoint hosted by the native app's backend to the native app itself. The method by which a native app receives such data follows {{Section 7 of !RFC8252}}. The native app MUST then validate the binding.
Alternatively, the client MAY require the user to re-authenticate (i.e., re-establish the session with the native app user) in the external user-agent (e.g., the browser). This approach is less recommended because it degrades usability.


Note that when redirecting to the origin or native app where the user-agent session is in place, the client MUST NOT expose the returned location in a way that is controllable by an attacker. Otherwise, an attacker could tamper with the returned location to leak authorization credentials via an open redirect.


# Security Considerations {#Security}

Security considerations are described in {{AttacksMitigations}}.


# IANA Considerations {#IANA}

This document has no IANA actions.


--- back

# Acknowledgments {#Acknowledgements}
{:numbered="false"}

We would like to thank
[^acksAddNames]{: source="Tim W."}
Daniel Fett,
Wing Cheong Lau,
Julien Lecomte,
Aaron Parecki,
Guido Schmitz, and
Xianbo Wang

[^acksAddNames]: TODO add names, sort by last name.
for their valuable feedback and contributions to this document.

# Document History
{:numbered="false"}

[[ To be removed from the final specification ]]

-01

* Updated temporary title
* Added introductory paragraphs, replaced placeholders
* Clarified issuer does not uniquely identify client config
* Cleaned up acknowledgement list

-00

* Initial version
