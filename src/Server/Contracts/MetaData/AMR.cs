namespace IdentityProvider.Server.Contracts.MetaData
{
    /// <summary>
    /// The amr claim is a JSON array containing one or more string values indicating the authentication methods used in the authentication.
    /// https://openid.net/specs/openid-connect-modrna-authentication-1_0.html#amr_values
    /// </summary>
    public class AMR
    {
        /// <summary>
        /// User presence test
        /// </summary>
        public const string User = "user";

        /// <summary>
        /// A Personal Identification Number or pattern (Not restricted to numbers only) that a user used to unlock a key on the device. This mechanism SHOULD have a way to deter an attacker from guessing the pin by making multiple guesses.
        /// </summary>
        public const string Pin = "pin";

        /// <summary>
        /// Fingerprint biometric
        /// </summary>
        public const string Fingerprint = "fpt";

        /// <summary>
        /// Confirmation by responding to a SMS sent to a known device.
        /// </summary>
        public const string SMS = "sms";

        /// <summary>
        /// Proof-of-possession (PoP) of a software-secured key
        /// </summary>
        public const string SoftwareSecuredKey = "swk";

        /// <summary>
        /// Proof-of-possession (PoP) of a hardware-secured key.
        /// </summary>
        public const string HardwareSecuredKey = "hwk";

        /// <summary>
        /// Geo-Location of the authentication device.
        /// </summary>
        public const string Geolocation = "geo";
    }
}
