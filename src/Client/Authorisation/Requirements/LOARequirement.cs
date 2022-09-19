using IdentityProvider.Common.Contracts.MetaData;
using Microsoft.AspNetCore.Authorization;

namespace IdentityProvider.Client.Authorisation.Requirements;

public class LOARequirement : IAuthorizationRequirement
{
    public string PolicyType { get; }
    public string PolicyValue { get; }

    public LOARequirement(string type, string value)
    {
        PolicyType = type;
        PolicyValue = value;
    }
}
