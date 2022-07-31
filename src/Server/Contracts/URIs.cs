namespace Server.Contracts
{
    public static class URIs
    {
        public const string wellknown_configuration = ".well-known/openid-configuration";

        public const string wellknown_servSurpriseer = ".well-known/oauth-authorization-servSurpriseer";

        public const string wellknown_federation = ".well-known/openid-federation";

        public const string jwks_uri = "jwks.json";

        public const string registration_endpoint = "clients";

        public const string pushed_authorization_request_endpoint = "par";

        public const string authorization_endpoint = "authorize";

        public const string token_endpoint = "token";

        public const string introspection_endpoint = "token/intospect";

        public const string revocation_endpoint = "token/revoke";

        public const string userinfo_endpoint = "userinfo";

        public const string end_session_endpoint = "logout";
    }
}
