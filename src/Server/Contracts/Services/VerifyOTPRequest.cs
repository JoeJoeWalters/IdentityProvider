namespace IdentityProvider.Server.Contracts.Services;

/// <summary>
/// Request to verify an OTP
/// </summary>
public class VerifyOTPRequest
{
    /// <summary>
    /// The unique identifier for the send action
    /// </summary>
    public string Identifier { get; set; } = string.Empty;

    /// <summary>
    /// The value we want to verify against the sent OTP
    /// </summary>
    public string Value { get; set; } = string.Empty;
}
