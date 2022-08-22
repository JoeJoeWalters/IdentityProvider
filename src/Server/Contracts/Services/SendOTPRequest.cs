namespace IdentityServer.Server.Contracts.Services
{
    /// <summary>
    /// Different delivery method types
    /// </summary>
    public enum SendOTPDeliveryMethod
    {
        /// <summary>
        /// (Email address)
        /// </summary>
        Email,

        /// <summary>
        /// SMS (Text Message)
        /// </summary>
        SMS,

        /// <summary>
        /// Voice mail
        /// </summary>
        Voice,

        /// <summary>
        /// If a mobile app is available, send a push notification
        /// </summary>
        PushNotification
    }

    /// <summary>
    /// Request to send an OTP
    /// </summary>
    public class SendOTPRequest
    {
        /// <summary>
        /// The unique identifer so the OTP can be verified later with the same expected Id (e.g. user id or device id)
        /// </summary>
        public string Identifier { get; set; } = string.Empty;

        /// <summary>
        /// The OTP Value to be sent (If left empty one will be generated for you)
        /// </summary>
        public string Value { get; set; } = string.Empty;

        /// <summary>
        /// What method of delivery? e.g. email, SMS etc.
        /// </summary>
        public SendOTPDeliveryMethod DeliveryMethod { get; set; } = SendOTPDeliveryMethod.SMS;

        /// <summary>
        /// The string that defines the delivery medium (e.g. phone number, email address)
        /// </summary>
        public string DeliveryValue { get; set; } = string.Empty; 
    }
}
