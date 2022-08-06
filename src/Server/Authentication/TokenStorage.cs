using Microsoft.IdentityModel.Tokens;

namespace Server.Authentication
{
    /// <summary>
    /// 
    /// </summary>
    public class TokenStorage : ITokenStorage
    {
        private readonly Dictionary<string, SecurityToken> _tokens;

        /// <summary>
        /// 
        /// </summary>
        public TokenStorage()
        {
            _tokens = new Dictionary<string, SecurityToken>();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public string Add(SecurityToken token)
        {
            String id = (new Guid()).ToString();
            _tokens.Add(id, token);
            return id;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public SecurityToken Retrieve(string id)
        {
            SecurityToken token = _tokens[id];
            _tokens.Remove(id);
            return token;
        }
    }
}
