using Microsoft.IdentityModel.Tokens;

namespace Server.Authentication
{
    public interface ITokenStorage
    {
        String Add(SecurityToken token);

        SecurityToken Retrieve(String id);
    }
}
