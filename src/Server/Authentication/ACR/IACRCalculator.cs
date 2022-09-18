using System.IdentityModel.Tokens.Jwt;

namespace IdentityProvider.Server.Authentication.ACR
{
    /// <summary>
    /// 
    /// </summary>
    public interface IACRCalculator
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        JwtSecurityToken AssignACR(JwtSecurityToken token);
    }
}
