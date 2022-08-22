using IdentityServer.Server.Contracts.Services;

namespace IdentityServer.Server.Services
{
    /// <summary>
    /// Mock OTP Service (Won't actually send requests)
    /// </summary>
    public class MockOTPService : IOTPService
    {
        private const string _otpDefaultValue = "000000";

        private readonly Dictionary<string, SendOTPRequest> _otpRequests;
        private readonly ILogger<MockOTPService> _logger;

        /// <summary>
        /// Default constructor
        /// </summary>
        public MockOTPService(ILogger<MockOTPService> logger)
        {
            _otpRequests = new Dictionary<string, SendOTPRequest>();
            _logger = logger;
        }

        /// <summary>
        /// Request to send an OTP
        /// </summary>
        /// <param name="request">The OTP Request object</param>
        /// <returns>The OTP Response object</returns>
        public async Task<SendOTPResponse> SendOTP(SendOTPRequest request)
        {
            // No matter the request the OTP is always the default for the mock service
            request.Value = _otpDefaultValue;

            // Store the OTP for verification later
            _otpRequests.Add(request.Identifier, request);

            SendOTPResponse result = new SendOTPResponse() { Success = true, Value = request.Value, Identifier = request.Identifier };

            return await Task.FromResult(result);
        }

        /// <summary>
        /// Verify an OTP that was sent
        /// </summary>
        /// <param name="request">The OTP request object</param>
        /// <returns>Verified?</returns>
        public async Task<Boolean> VerifyOTP(VerifyOTPRequest request)
        {
            if (_otpRequests.TryGetValue(request.Identifier, out SendOTPRequest? origionalRequest))
            {
                Boolean result = (origionalRequest != null && origionalRequest.Value == request.Value);
                return await Task.FromResult(result);
            }
            else
                return await Task.FromResult(false);
        }
    }
}
