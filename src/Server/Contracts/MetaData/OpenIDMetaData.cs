namespace IdentityProvider.Server.Contracts.MetaData;

/// <summary>
/// Data returned by the Well Known endpoint
/// </summary>
public class OpenIDMetaData
{
    /// <summary>
    /// The configured issuer URL(server identifier), e.g.https://c2id.com.
    /// </summary>
    public string issuer { get; set; } = string.Empty;

    /// <summary>
    /// The public server JWK set URL.
    /// </summary>
    public Uri? jwks_uri { get; set; }

    /// <summary>
    /// The OAuth 2.0 / OpenID Connect client registration endpoint URL.
    /// </summary>
    public Uri? registration_endpoint { get; set; }

    /// <summary>
    /// The OAuth 2.0 pushed authorisation request (PAR) endpoint URL.
    /// </summary>
    public Uri? pushed_authorization_request_endpoint { get; set; }

    /// <summary>
    /// The OAuth 2.0 authorisation endpoint URL.
    /// </summary>
    public Uri? authorization_endpoint { get; set; }

    /// <summary>
    /// The OAuth 2.0 token endpoint URL.
    /// </summary>
    public Uri? token_endpoint { get; set; }

    /// <summary>
    /// The OAuth 2.0 token introspection endpoint URL.
    /// </summary>
    public Uri? introspection_endpoint { get; set; }

    /// <summary>
    /// The OAuth 2.0 token revocation endpoint URL.
    /// </summary>
    public Uri? revocation_endpoint { get; set; }

    /// <summary>
    /// The OpenID Connect UserInfo endpoint URL.
    /// </summary>
    public Uri? userinfo_endpoint { get; set; }

    /// <summary>
    /// The OpenID Connect logout endpoint URL, omitted if disabled.
    /// </summary>
    public Uri? end_session_endpoint { get; set; }

    /// <summary>
    /// The OpenID Connect logout endpoint URL, omitted if disabled.
    /// </summary>
    public List<string> grant_types_supported { get; set; } = new List<string>();

    /// <summary>
    /// List of the supported OAuth 2.0 response_type values.
    /// </summary>
    public List<string> response_types_supported { get; set; } = new List<string>();

    /// <summary>
    /// List of the supported OAuth 2.0 response_mode values.
    /// </summary>
    public List<string> response_modes_supported { get; set; } = new List<string>();


    /*

    [ check_session_iframe ] {string} The OpenID Connect check session iframe URL, omitted if disabled.

    prompt_values_supported {string array} List of the support OAuth 2.0 authorisation / OpenID authentication request prompt parameter values.

    code_challenge_methods_supported {string array} List of the supported transformation methods by the authorisation code verifier for Proof Key for Code Exchange (PKCE).

    [ authorization_response_iss_parameter_supported ] {true|false} Indicates support for the iss authorisation response parameter. If omitted the default value is false.

    token_endpoint_auth_methods_supported {string array} List of the supported client authentication methods at the OAuth 2.0 token endpoint and other endpoints.

    [ token_endpoint_auth_signing_alg_values_supported ] {string array} List of the supported JWS algorithms for JWT-based client authentication at the OAuth 2.0 token endpoint and other endpoints, omitted or empty if none.

    [ request_object_signing_alg_values_supported ] {string array} List of the supported JWS algorithms for JWT-secured authorisation requests (JAR) / OpenID Connect request objects, omitted or empty if none.

    [ request_object_encryption_alg_values_supported ] {string array} List of the supported JWE encryption algorithms for JWT-secured authorisation requests (JAR) / OpenID Connect request objects, omitted or empty if none.

    [ request_object_encryption_enc_values_supported ] {string array} List of the supported JWE encryption methods for JWT-secured authorisation requests (JAR) / OpenID Connect request objects, omitted or empty if none.

    [ authorization_signing_alg_values_supported ] {string array} List of the supported JWS algorithms for signed authorisation responses (JARM).

    [ authorization_encryption_alg_values_supported ] {string array} List of the supported JWE algorithms for encrypted authorisation responses (JARM).

    [ authorization_encryption_enc_values_supported ] {string array} List of the supported JWE content encryption methods for encrypted authorisation responses (JARM).

    id_token_signing_alg_values_supported {string array} List of the supported JWS algorithms for securing the issued ID tokens.

    [ id_token_encryption_alg_values_supported ] {string array} List of the supported JWE algorithms for securing the issued ID tokens, omitted or empty if none.

    [ id_token_encryption_enc_values_supported ] {string array} Lisf of the supported JWE encryption methods for securing the issued ID tokens, omitted or empty if none.

    userinfo_signing_alg_values_supported {string array} List of the supported JWS algorithms for securing the claims returned at the UserInfo endpoint.

    [ userinfo_encryption_alg_values_supported ] {string array} List of the supported JWE encryption algorithms for securing the claims returned at the UserInfo endpoint, omitted or empty if none.

    [ userinfo_encryption_enc_values_supported ] {string array} List of the supported JWE encryption methods for securing the claims returned at the UserInfo endpoint, omitted or empty if none.

    subject_types_supported {string array} List of the supported subject (end-user) identifier types.
    */

    /// <summary>
    /// List of the supported Authentication Context Class References (ACRs)
    /// </summary>
    public List<string> acr_values_supported { get; set; } = new List<string>();

    /*
    display_values_supported {string array} List of the supported display parameters.

    scopes_supported {string array} List of the supported scope values. Certain values may be omitted for privacy reasons.

    claim_types_supported {string array} List of the supported OpenID Connect claim types.

    claims_supported {string array} List of the supported OpenID Connect claims. Certain values may be omitted for privacy reasons.

    [ claims_locales_supported ] {string array} List of the supported OpenID Connect claims locales, omitted or empty if none.

    [ ui_locales_supported ] {string array} List of the supported UI locales, omitted or empty if none.

    claims_parameter_supported {true|false} Indicates support for the claims OpenID authentication request parameter.

    request_parameter_supported {true|false} Indicates support for the request authorisation request parameter.

    request_uri_parameter_supported {true|false} Indicates support for the request_uri authorisation request parameter.

    require_request_uri_registration {true|false} Indicates whether the request_uris must be registered for a client.

    request_uri_quota {integer} Indicates the maximum number of request_uris that can be registered for a client (custom Connect2id server specific parameter).

    [ require_pushed_authorization_requests ] {true|false} Indicates whether authorisation requests must be pushed via the PAR endpoint. If omitted the default value is false.

    [ tls_client_certificate_bound_access_tokens ] {true|false} Indicates support for issuing client X.509 certificate bound access tokens. If omitted the default value is false.

    [ dpop_signing_alg_values_supported ] {string array} List of the supported JWS algorithms for DPoP proof JWTs, omitted or empty if none.

    [ frontchannel_logout_supported ] {true|false} Indicates support for OpenID Connect front-channel logout. If omitted the default value is false.

    [ frontchannel_logout_session_supported ] {true|false} Indicates whether the session ID (sid) will be included in OpenID Connect front-channel logout notifications. If omitted the default value is false.

    [ backchannel_logout_supported ] {true|false} Indicates support for OpenID Connect back-channel logout. If omitted the default value is false.

    [ backchannel_logout_session_supported ] {true|false} Indicates whether the session ID (sid) will be included in OpenID Connect back-channel logout notifications. If omitted the default value is false.

    [ client_registration_types_supported ] {string list} List of the supported OpenID Connect Federation 1.0 client registration types, omitted if the federation protocol is disabled.

    [ organization_name ] {string} The name of the organisation in the OpenID Connect Federation 1.0 deployment, omitted if the federation protocol is disabled or a name isn't specified.

    [ federation_registration_endpoint ] {string} The OpenID Connect Federation 1.0 registration endpoint URL, omitted if the federation protocol is disabled.

    [ client_registration_authn_methods_supported ] {object} The supported authentication methods for automatic registration requests in OpenID Connect Federation, omitted if the federation protocol is disabled.

    [ verified_claims_supported ] {true|false} Indicates support for OpenID Connect for Identity Assurance 1.0. If omitted the default value is false.

    [ trust_frameworks_supported ] {string array} List of the supported trust frameworks if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none.

    [ evidence_supported ] {string array} List of the evidence types if OpenID Connect Identity for Assurance 1.0 is supported, omitted or empty if none.

    [ documents_supported ] {string array} List of the document types if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none.

    [ id_documents_supported ] {string array} List of the identity document types if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none. Deprecated.

    [ documents_methods_supported ] {string array} List of the supported coarse identity verification methods for evidences of type document if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none.

    [ documents_validation_methods_supported ] {string array} List of the supported validation methods for evidences of type document if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none.

    [ documents_verification_methods_supported ] {string array} List of the supported person verification methods for evidences of type document if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none.

    [ id_documents_verification_methods_supported ] {string array} List of the identity document verification methods if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none. Deprecated.

    [ electronic_records_supported ] {string array} List of the supported electronic record types if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none.

    [ claims_in_verified_claims_supported ] {string array} List of the supported verified claims if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none.

    [ attachments_supported ] {string array} List of the supported attachment types (embedded, external) if OpenID Connect for Identity Assurance 1.0 is supported, empty if none.

    [ digest_algorithms_supported ] {string array} List of the the supported digest algorithms for external attachments if OpenID Connect for Identity Assurance 1.0 is supported, omitted or empty if none. The "sha-256" algorithm is always supported for external external attachments.

    [ op_policy_uri ] {string} The privacy policy document URL, omitted if none.

    [ op_tos_uri ] {string} The terms of service document URL, omitted if none.

    [ service_documentation ] {string} The service documentation URL, omitted if none.

            */
}
