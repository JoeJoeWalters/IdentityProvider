using IdentityProvider.Common.Contracts;
using IdentityProvider.Common.Contracts.Tokens;
using IdentityProvider.Common.Providers;
using IdentityProvider.Server.Authentication;
using IdentityProvider.Server.Contracts.Tokens;
using IdentityProvider.Server.Helpers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace IdentityProvider.Server.Controllers;

/// <summary>
/// 
/// </summary>
[ApiController]
public class TokenController : ControllerBase
{
    private readonly ILogger<TokenController> _logger;
    private readonly IAuthenticator _userAuthenticator;
    private readonly ServerSettings _serverSettings;
    private readonly ITimeProvider _timeProvider;

    // https://vmsdurano.com/-net-core-3-1-signing-jwt-with-rsa/
    private SigningCredentials _signingCredentials { get; set; }


    /// <summary>
    /// 
    /// </summary>
    /// <param name="logger"></param>
    /// <param name="userAuthenticator"></param>
    /// <param name="serverSettings"></param>
    /// <param name="signingCredentials"></param>
    public TokenController(
        ILogger<TokenController> logger,
        IAuthenticator userAuthenticator,
        ServerSettings serverSettings,
        SigningCredentials signingCredentials,
        ITimeProvider timeProvider)
    {
        _logger = logger;
        _userAuthenticator = userAuthenticator;
        _serverSettings = serverSettings;
        _signingCredentials = signingCredentials;
        _timeProvider = timeProvider;
    }

    // https://connect2id.com/products/server/docs/api/par
    /// <summary>
    /// Submit the request parameters directly to the server before sending the end-user to the authorisation endpoint for login and consent.
    /// </summary>
    /// <returns></returns> 
    [HttpGet]
    [Route(URIs.pushed_authorization_request_endpoint)]
    public ActionResult PushedAuthorisationRequests()
    {
        return new OkResult();
    }

    // https://connect2id.com/products/server/docs/api/token
    /// <summary>
    /// Post an OAuth 2.0 grant (code, refresh token, resource owner password credentials, client credentials) to obtain an ID and / or access token.
    /// </summary>
    /// <returns></returns> 
    [HttpGet]
    [Route(URIs.token_endpoint)]
    public ActionResult Token([FromQuery] TokenRequest request)
    {
        DateTime now = _timeProvider.Now(); // Fixed point in time
        long unixTime = (new DateTimeOffset(now)).ToUnixTimeSeconds();

        var handler = new JwtSecurityTokenHandler();

        // No authentication needed if a refresh token is being given
        if (request.Type == GrantTypes.RefreshToken)
        {
            // https://stackoverflow.com/questions/57481524/what-is-encoded-in-refresh-token
            // https://stackoverflow.com/questions/39890282/oauth2-0-what-should-be-the-content-format-of-refresh-token-before-encryption
            // Go look up the corresponding given token and refresh it, add to the expiry and hand back again

            // Generate the new token from the refresh token as that holds the same data that was previously agreed
            JwtSecurityToken token = (new JwtSecurityToken(request.Refresh_Token)).GenerateFromRefreshToken(_serverSettings.AccessTokenExpiry, now, _signingCredentials, _serverSettings);

            // Generate the new refresh token from the generated token
            JwtSecurityToken refreshToken = token.GenerateRefreshToken(_serverSettings.RefreshTokenExpiry, now, _signingCredentials, _serverSettings);

            try
            {

                return new OkObjectResult(
                    new OAuthTokenSuccess()
                    {
                        AccessToken = handler.WriteToken(token),
                        ExpiresIn = _serverSettings.AccessTokenExpiry,
                        RefreshToken = handler.WriteToken(refreshToken),
                        Scope = "",
                        TokenType = "bearer"
                    });
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(
                    new TokenFailure()
                    {
                        Reason = TokenFailure.ReasonType.invalid_request,
                        ReasonDescription = "Could not process given refresh token",
                        ReasonUri = ""
                    });
            }
        }
        else
        {

            // Check the client id and secret being asked for;
            JwtSecurityToken token = _userAuthenticator.AuthenticateOAuth(request);
            if (token != null)
            {
                JwtSecurityToken refreshToken = token.GenerateRefreshToken(_serverSettings.RefreshTokenExpiry, now, _signingCredentials, _serverSettings);

                return new OkObjectResult(
                    new OAuthTokenSuccess()
                    {
                        AccessToken = handler.WriteToken(token),
                        ExpiresIn = _serverSettings.AccessTokenExpiry,
                        RefreshToken = handler.WriteToken(refreshToken),
                        Scope = "",
                        TokenType = "bearer"
                    });
            }
            else
            {
                return new BadRequestObjectResult(
                    new TokenFailure()
                    {
                        Reason = TokenFailure.ReasonType.unauthorized_client,
                        ReasonDescription = "Reason for the failure here",
                        ReasonUri = ""
                    });
            }
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
    /// <summary>
    /// Validate an access token and retrieve its underlying authorisation (for resource servers).
    /// </summary>
    /// <returns></returns> 
    [HttpGet]
    [HttpPost]
    [Route(URIs.introspection_endpoint)]
    public ActionResult TokenIntrospection([FromQuery] TokenIntrospectionRequest request)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(_serverSettings.PublicKey.ToCharArray());

        JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
        TokenValidationParameters validationParameters = new TokenValidationParameters
        {
            ValidIssuer = _serverSettings.Issuer,
            ValidAudiences = _serverSettings.Audiences.Select(aud => aud.Name).ToArray(),
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireAudience = true,
            IssuerSigningKeys = new List<SecurityKey> { new RsaSecurityKey(rsa) }
        };

        try
        {
            ClaimsPrincipal principal = handler.ValidateToken(request.token, validationParameters, out SecurityToken jsonToken);
            JwtSecurityToken token = jsonToken as JwtSecurityToken;

            // Token validation is seemingly avoiding if the exp date < datetime.utcnow so do it manually
#warning ValidateToken should do this right? Maybe because of clock offset? Code some "wiggle room" in maybe?
            if (token.Payload.Exp.Value <= (new DateTimeOffset(_timeProvider.Now())).ToUnixTimeSeconds())
                throw new SecurityTokenExpiredException();

            string type = token.Header["typ"].ToString().ToLower();

            if ((type.ToLower().IsNullOrEmpty() ? "jwt" : type) == request.token_type_hint.ToLower())
                return new OkObjectResult(
                    JsonConvert.SerializeObject(
                        new TokenIntrospectionResponse() { active = true, scope = token.Claims.Where(claim => claim.Type.ToLower() == "scope").FirstOrDefault().Value, exp = token.Payload.Exp },
                        Formatting.Indented,
                        new JsonSerializerSettings
                        {
                            NullValueHandling = NullValueHandling.Ignore
                        }));
        }
        catch (SecurityTokenInvalidAudienceException audEx)
        {

        }
        catch (SecurityTokenInvalidAlgorithmException algEx)
        {

        }
        catch (SecurityTokenInvalidIssuerException issEx)
        {

        }
        catch (SecurityTokenInvalidSignatureException sigEx)
        {

        }
        catch (SecurityTokenInvalidLifetimeException lifEx)
        {

        }
        catch (SecurityTokenExpiredException expEx)
        {

        }
        catch (Exception ex)
        {
        }

        return new UnauthorizedObjectResult(
            JsonConvert.SerializeObject(
                new TokenIntrospectionResponse() { active = false },
                Formatting.Indented,
                new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore
                }));
    }

    // https://connect2id.com/products/server/docs/api/token-revocation
    /// <summary>
    /// Revoke an obtained access or refresh token.
    /// </summary>
    /// <returns></returns> 
    [HttpPost]
    [Route(URIs.revocation_endpoint)]
    public ActionResult TokenRevocation()
    {
        return new OkResult();
    }

    // https://connect2id.com/products/server/docs/api/logout
    /// <summary>
    /// Let a client application (OpenID relying party) notify the Identity Provider (IdP) that an end-user has logged out of the application
    /// </summary>
    /// <returns></returns> 
    [HttpGet]
    [Route(URIs.revocation_endpoint)]
    public ActionResult LogOut()
    {
        return new OkResult();
    }
}