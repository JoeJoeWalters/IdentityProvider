﻿using IdentityProvider.Common.Contracts.MetaData;
using IdentityProvider.Common.Contracts.Tokens;
using IdentityProvider.Common.Exceptions;
using IdentityProvider.Common.Providers;
using IdentityProvider.Server.Authentication.ACR;
using IdentityProvider.Server.Contracts.Services;
using IdentityProvider.Server.Contracts.Tokens;
using IdentityProvider.Server.Helpers;
using IdentityProvider.Server.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;

namespace IdentityProvider.Server.Authentication;

/// <summary>
/// Standard user authenticator that reads from a Json file in a given location
/// </summary>
public class Authenticator : IAuthenticator
{
    /// <summary>
    /// Local cached list of users
    /// </summary>
    private readonly AccessControl _accessControl;

    private readonly ILogger<Authenticator> _logger;
    private readonly ServerSettings _serverSettings;
    private readonly SigningCredentials _signingCredentials;
    private readonly IPinService _pinService;
    private readonly IOTPService _otpService;
    private readonly IHashService _hashService;
    private readonly ITokenStorage _tokenStorage;
    private readonly IACRCalculator _acrCalculator;
    private readonly ITimeProvider _timeProvider;

    public TokenValidationParameters JWTValidationParams { get; internal set; }

    /// <summary>
    /// Default Constructor
    /// </summary>
    public Authenticator()
    {

    }

    public Authenticator(
        ILogger<Authenticator> logger,
        TokenValidationParameters tokenValidationParameters,
        SigningCredentials signingCredentials,
        ServerSettings serverSettings,
        IHashService hashService,
        IPinService pinService,
        IOTPService otpService,
        ITokenStorage tokenStorage,
        IACRCalculator acrCalculator,
        ITimeProvider timeProvider,
        AccessControl accessControl)
    {
        _logger = logger;
        this.JWTValidationParams = tokenValidationParameters; // Assign the validator for the JWT tokens
        _serverSettings = serverSettings;
        _signingCredentials = signingCredentials;
        _hashService = hashService;
        _pinService = pinService;
        _otpService = otpService;
        _tokenStorage = tokenStorage;
        _acrCalculator = acrCalculator;
        _accessControl = accessControl;
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Custom grant type fulfillment
    /// </summary>
    /// <param name="tokenRequest"></param>
    /// <returns></returns>
    public JwtSecurityToken AuthenticateCustom(TokenRequest tokenRequest)
        => Task.Run(() => AuthenticateCustomAsync(tokenRequest)).Result;

    /// <summary>
    /// Custom grant type fulfillment
    /// </summary>
    /// <param name="tokenRequest"></param>
    /// <returns></returns>
    public async Task<JwtSecurityToken> AuthenticateCustomAsync(TokenRequest tokenRequest)
    {
        SecurityData data = null;
        DateTime now = _timeProvider.Now(); // Fixed point in time to be used in this method as a point of reference
        string amr = string.Empty;

        switch (tokenRequest.Type)
        {
            case CustomGrantTypes.Pin:

                data = _accessControl
                        .Users
                        .Where(user =>
                        {
                            return
                                now >= user.Created &&
                                now <= user.Expires &&
                                user.Username == tokenRequest.Username &&
                                _pinService.CompareHashedDigits(tokenRequest.Pin, user.Id, user.Pin) &&
                                user.ClientId == tokenRequest.Client_Id;
                        }).FirstOrDefault();

                amr = AMR.Pin;

                break;

            case CustomGrantTypes.OTP:

                if (await _otpService.VerifyOTP(new VerifyOTPRequest() { Identifier = tokenRequest.OTPIdentifier, Value = tokenRequest.OTP }))
                {
                    data = _accessControl
                            .Users
                            .Where(user =>
                            {
                                return
                                    now >= user.Created &&
                                    now <= user.Expires &&
                                    user.Username == tokenRequest.Username &&
                                    user.ClientId == tokenRequest.Client_Id;
                            }).FirstOrDefault();

                    amr = AMR.SMS;
                }

                break;
        }

        return await GenerateTokenFromSecurityData(data, amr, now, tokenRequest);
    }

    /// <summary>
    /// OAuth grant type mode fulfillment
    /// </summary>
    /// <param name="tokenRequest"></param>
    /// <returns></returns>
    public JwtSecurityToken AuthenticateOAuth(TokenRequest tokenRequest)
        => Task.Run(() => AuthenticateOAuthAsync(tokenRequest)).Result;

    /// <summary>
    /// OAuth grant type mode fulfillment
    /// </summary>
    /// <param name="tokenRequest"></param>
    /// <returns></returns>
    public async Task<JwtSecurityToken> AuthenticateOAuthAsync(TokenRequest tokenRequest)
    {
        SecurityData data = null;
        JwtSecurityToken response = null;
        DateTime now = _timeProvider.Now(); // Fixed point in time as a point of reference
        string amr = string.Empty;

        try
        {
            switch (tokenRequest.Type)
            {
                case GrantTypes.ClientCredentials:

                    data = _accessControl
                        .Clients
                        .Where(client =>
                        {
                            return
                                now >= client.Created &&
                                now <= client.Expires &&
                                client.Id == tokenRequest.Client_Id &&
                                client.Secret == tokenRequest.Client_Secret;
                        }).Select(client => new SecurityData() { Id = client.Id, ClientId = client.Id }).FirstOrDefault();

                    amr = AMR.ClientCredentials;

                    response = await GenerateTokenFromSecurityData(data, amr, now, tokenRequest);

                    break;

                case GrantTypes.Password:

#warning This is not efficient, creating the hash on the fly because we are using userid of the comparer for the hash salt so revisit later (it's only a sandbox service for now)
                    data = _accessControl
                        .Users
                        .Where(user =>
                        {
                            return
                                now >= user.Created &&
                                now <= user.Expires &&
                                user.Username == tokenRequest.Username &&
                                user.Password == _hashService.CreateHash($"{user.Id}{tokenRequest.Password}") &&
                                user.ClientId == tokenRequest.Client_Id;
                        }).FirstOrDefault();

                    amr = AMR.Password;

                    response = await GenerateTokenFromSecurityData(data, amr, now, tokenRequest);

                    break;

                case GrantTypes.AuthorisationCode:

                    try
                    {
                        response = _tokenStorage.Retrieve(tokenRequest.Code, tokenRequest.CodeVerifier);
                    }
                    catch(SecurityTokenAuthenticationCodeNotFound notFoundEx)
                    {
                        // Security token either wasn't there or wasn't matched with the PKCE method
                    }
                    catch(Exception ex)
                    {
                        // Some other error
                    }

                    break;

                default:

                    break;
            }
        }
        catch (Exception ex)
        {
        };

        return response;

    }

    private async Task<JwtSecurityToken> GenerateTokenFromSecurityData(SecurityData data, string amr, DateTime now, TokenRequest tokenRequest)
    {
        long unixTime = (new DateTimeOffset(now)).ToUnixTimeSeconds();

        if (data != null)
        {
            // Generate a new JWT Header to wrap the token
            JwtHeader header = new JwtHeader(_signingCredentials);
            header.Add("kid", _serverSettings.PublicKey.ComputeSha1Hash());

            // Cross reference the requested scopes against the available scopes to get the delta
            List<String> requestedScopes = String.IsNullOrEmpty(tokenRequest.Scope) ? new List<String>() : tokenRequest.Scope.Split(' ').Select(x => x.Trim()).ToList();
            List<Claim> claims = requestedScopes.Where(requestedScope => data.Scopes.Contains(requestedScope)).Select(requestedScope => new Claim("scope", requestedScope)).ToList();

            // Add in any other required claims
            claims.AddRange(data.Claims ?? new List<Claim>());
            claims.Add(new Claim("sub", data.Id)); // Add the user id as the subject (sub claim) 
            claims.Add(new Claim("ait", unixTime.ToString())); // Creation Time claim
            
            // Create the content of the JWT Token with the appropriate expiry date
            JwtPayload secPayload = new JwtPayload(
                _serverSettings.Issuer,
                _serverSettings.Audiences.Where(aud => aud.Primary).FirstOrDefault().Name,
                claims,
                now.AddSeconds(-1), // For the bots
                now.AddSeconds(_serverSettings.AccessTokenExpiry));

            // Add the authentication method to the payload's claim (it's an array)
            // secPayload.Amr.Add(amr); does not work as the IList item is readonly for when it is read back
            // so assign via the parent "Add" instead.
            var amrValues = new List<string>() { amr }.Distinct().ToArray();
            if (amrValues.Any())
            {
                secPayload.Add("amr", amrValues);
            }

            // Generate the final token from the header and it's payload
            JwtSecurityToken token = new JwtSecurityToken(header, secPayload);

            // Apply the ACR policy by evaluating the otken
            token = _acrCalculator.AssignACR(token);

            return await Task.FromResult<JwtSecurityToken>(token);
        }
        else
        {
        }

#warning "TODO"
        throw new Exception();
    }

    /// <summary>
    /// Take a token (usually from the auth token in the header) and validate the
    /// user
    /// </summary>
    /// <param name="securityToken">The security token, usually from the header</param>
    /// <returns>The user that was found and validated, a null will be returned if no user was validated</returns>
    public JwtSecurityToken AuthenticateToken(String securityToken)
        => Task.Run(() => AuthenticateTokenAsync(securityToken)).Result;

    public async Task<JwtSecurityToken> AuthenticateTokenAsync(String securityToken)
    {
        // Not authorised by default
        SecurityData result = null;

        // The time the token started to validate so it is consistent
        DateTime tokenReceivedTime = _timeProvider.Now();

        try
        {
            // Basic authentication requested
            AuthenticationHeaderValue authHeader;
            try
            {
                authHeader = AuthenticationHeaderValue.Parse(securityToken);
            }
            catch
            {
                throw new Exception("Authentication Header Is Malformed");
            }

            String token = authHeader.Parameter; // Get the token from the header

            switch (authHeader.Scheme.ToLower().Trim())
            {
                case "oauth":
                case "bearer":

                    // Expects bearer to be JWT encoded       
                    // https://jwt.io/
                    SecurityToken jwtToken = null;
                    JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

                    try
                    {
                        jwtToken = tokenHandler.ReadToken(token);
                    }
                    catch { }

                    // No failure, must be a valid JWT encoded bearer
                    if (jwtToken != null)
                    {
                        // TODO: Get the user details from the JWT Token instead of the access control list
                        JwtSecurityToken jwtSecurityToken = (JwtSecurityToken)jwtToken;

                        // Check the expiry date of the token, if it has expired we need to tell the source
                        // system and get them to request a new token with the refresh token
                        if (!(jwtSecurityToken.ValidFrom <= tokenReceivedTime &&
                            jwtSecurityToken.ValidTo >= tokenReceivedTime))
                            throw new Exception("Lifetime validation failed. The token is expired");

                        // Validate the token and get the principal
                        SecurityToken validatedToken = null;
                        IPrincipal principal = null;
                        try
                        {
                            principal = tokenHandler.ValidateToken(
                                                        token,
                                                        JWTValidationParams,
                                                        out validatedToken);
                        }
                        catch { }

                        // Did we get a principal?
                        if (principal != null && validatedToken != null)
                        {
                            return await Task.FromResult<JwtSecurityToken>((JwtSecurityToken)validatedToken);
                        }
                    }
                    else
                    {
                        throw new Exception("Not a JWT token");
                    }

                    break;

                default:

                    break;
            }
        }
        catch (Exception ex)
        {
            throw ex;
        }

#warning "TODO"
        throw new Exception();
    }

    /// <summary>
    /// Get the security data of a credential based on the username (for choosing what authentication options to display etc.)
    /// </summary>
    /// <returns></returns>
    public SecurityData GetByUsername(string username)
        => _accessControl
            .Users
            .Where(user =>
            {
                return user.Username == username;
            }).FirstOrDefault();
}
