using System;

namespace IdentityProvider.Common.Exceptions;

/// <summary>
/// 
/// </summary>
public class SecurityTokenAuthenticationCodeNotFound : Exception
{
    /// <summary>
    /// 
    /// </summary>
    public SecurityTokenAuthenticationCodeNotFound() : base("Token does not exist in token storage with the given authentication code")
    {

    }
}
