namespace IdentityProvider.Server.Contracts.MetaData
{
    /// <summary>
    /// https://www.rfc-editor.org/rfc/rfc6711.txt
    /// </summary>
    public class ACR
    {
        /// <summary>
        /// Little or no Assurance exists in the asserted Digital Identity - usually self-asserted; essentially a persistent identifier
        /// </summary>
        public const string LOALevel1 = "Level1";

        /// <summary>
        /// Assurance exists that the asserted Digital Identity is accurate; used frequently for self service applications
        /// </summary>
        public const string LOALevel2 = "Level2";

        /// <summary>
        /// High Assurance in the asserted Digital Identity's accuracy; used to access Protected Data
        /// </summary>
        public const string LOALevel3 = "Level3";

        /// <summary>
        /// Very high Assurance in the asserted Digital Identity's accuracy; used to access highly Protecte
        /// </summary>
        public const string LOALevel4 = "Level4";
    }
}
