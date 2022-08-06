using Server.Authentication;

namespace Server.Services
{
    /// <summary>
    /// Service for managing interactions with passcodes
    /// </summary>
    public class PasscodeService : IPasscodeService
    {
        private readonly IHashService _hashService;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="hashService"></param>
        public PasscodeService(IHashService hashService)
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
            for (int position = 0; position < value.Length; position++)
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
        public Boolean CompareHashedDigits(List<KeyValuePair<int, string>> digitsAndPositions, string salt, PasscodeData data)
        {
            foreach (KeyValuePair<int, string> toCompare in digitsAndPositions)
            {
                string hash = _hashService.CreateHash($"{toCompare.Key}{salt}{toCompare.Value}");
                if (data.HashedDigits[toCompare.Key] != hash)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Generate a list of random numbers related to the pin data available 
        /// </summary>
        /// <param name="data">The user's pin data</param>
        /// <param name="totalRequired">The amount of positions needed</param>
        /// <returns>A list of positions in that data</returns>
        public List<int> RandomPositions(PasscodeData data, int totalRequired)
        {
            List<int> result = new List<int>();

            if (data.HashedDigits?.Count >= totalRequired)
            {
                Random random = new Random();
                while (result.Count < totalRequired)
                {
                    int position = random.Next(0, data.HashedDigits.Count); // Get a random position between the bounds
                    if (!result.Contains(position)) // Make sure don't already have this position stored (don't want to ask for it twice, looks weird on the screen)
                        result.Add(position);
                }
            }
            else
            {
                // Not enough digits in the passcode to give you what you need to give all the positions possible instead 
                for (var i = 0; i < data.HashedDigits?.Count; i++)
                    result.Add(i);
            }

            return result.OrderBy(x => x).ToList();
        }
    }
}
