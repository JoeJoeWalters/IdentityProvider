using Server.Authentication;

namespace Server.Services
{
    /// <summary>
    /// Service for managing interactions with PIN Numbers
    /// </summary>
    public class PinService : IPinService
    {
        private readonly IHashService _hashService;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hashService"></param>
        public PinService(IHashService hashService)
        {
            _hashService = hashService;
        }

        /// <summary>
        /// Generate the hashed digits for a given passcode / pin number
        /// </summary>
        /// <param name="value">The value to split and generate the digits from</param>
        /// <param name="salt">The salt to add before the hashing</param>
        /// <returns>A list of hashed digits</returns>
        public List<string> ToHashedDigits(string value, string salt)
        {
            List<string> hashedValues = new List<string>();

            // Loop the string by number as we need the position of the digit to be hashed too
            for(int position = 0; position < value.Length; position ++)
            {
                hashedValues.Add(_hashService.CreateHash($"{position}{salt}{value[position]}")); // Position + Salt + Actual Value then hashed
            }

            return hashedValues;
        }

        /// <summary>
        /// Compare an incoming pin entry (digits and their position) to the held data for a credential
        /// </summary>
        /// <param name="digitsAndPositions">The list of the entered digits and their positions</param>
        /// <param name="salt">The salt for hash comparisons</param>
        /// <param name="data">The pin data for a user to compare against</param>
        /// <returns>Success or failure</returns>
        public Boolean CompareHashedDigits(List<KeyValuePair<int, string>> digitsAndPositions, string salt, PinData data)
        {
            foreach (KeyValuePair<int, string> toCompare in digitsAndPositions)
            {
                string hash = _hashService.CreateHash($"{toCompare.Key}{salt}{toCompare.Value}");
                if (data.HashedDigits[toCompare.Key] != hash)
                    return false;
            }

            return true;
        }
    }
}
