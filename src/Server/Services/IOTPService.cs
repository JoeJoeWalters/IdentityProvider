using IdentityProvider.Server.Contracts.Services;

namespace IdentityProvider.Server.Services
{
    /// <summary>
    /// Interface for service that sends one time passcodes
    /// </summary>
    public interface IOTPService
    {
        /// <summary>
        /// Request to send an OTP
        /// </summary>
        /// <param name="request">The OTP Request object</param>
        /// <returns>The OTP Response object</returns>
        Task<SendOTPResponse> SendOTP(SendOTPRequest request);

        /// <summary>
        /// Verify an OTP that was sent
        /// </summary>
        /// <param name="request">The OTP request object</param>
        /// <returns>Verified?</returns>
        Task<Boolean> VerifyOTP(VerifyOTPRequest request);
    }
}
