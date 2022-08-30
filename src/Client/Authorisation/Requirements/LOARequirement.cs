using IdentityProvider.Common.Contracts.MetaData;
using Microsoft.AspNetCore.Authorization;

namespace IdentityProvider.Client.Authorisation.Requirements
{
    public class LOARequirement : IAuthorizationRequirement
    {
        private readonly string _level = ACR.LOALevel1;
        public int Level { get => int.Parse(_level.Replace("LOALevel", String.Empty)); }

        public LOARequirement(string LOALevel)
        {
            _level = LOALevel;
        }
    }
}
