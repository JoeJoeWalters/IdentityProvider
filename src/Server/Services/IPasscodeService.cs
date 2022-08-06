using Server.Authentication;

namespace Server.Services
{
    /// <summary>
    /// Service for managing interactions with PIN Numbers
    /// </summary>
    public interface IPasscodeService
    {
        /// <summary>
        /// Generate the hashed digits for a given passcode / pin number
        /// </summary>
        /// <param name="value">The value to split and generate the digits from</param>
        /// <param name="salt">The salt to add before the hashing</param>
        /// <returns>A list of hashed digits</returns>
        List<string> ToHashedDigits(string value, string salt);

        /// <summary>
        /// Compare an incoming pin entry (digits and their position) to the held data for a credential
        /// </summary>
        /// <param name="digitsAndPositions">The list of the entered digits and their positions</param>
        /// <param name="salt">The salt for hash comparisons</param>
        /// <param name="data">The pin data for a user to compare against</param>
        /// <returns>Success or failure</returns>
        Boolean CompareHashedDigits(List<KeyValuePair<int, string>> digitsAndPositions, string salt, PasscodeData data);

        /// <summary>
        /// Generate a list of random numbers related to the pin data available 
        /// </summary>
        /// <param name="data">The user's pin data</param>
        /// <param name="totalRequired">The amount of positions needed</param>
        /// <returns>A list of positions in that data</returns>
        List<int> RandomPositions(PasscodeData data, int totalRequired);
    }
}
