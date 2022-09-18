namespace IdentityProvider.Server.Contracts.Services;

/// <summary>
/// Response back from the OTP Service
/// </summary>
public class SendOTPResponse
{
    /// <summary>
    /// Was it successful?
    /// </summary>
    public Boolean Success { get; set; } = false;

    /// <summary>
    /// If no value was provided to be sent it will generate one and return it in the response
    /// </summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>
    /// If no identifier was sent in then this is the generated Id
    /// </summary>
    public string Identifier { get; set; } = string.Empty;

}
