using System.Security.Claims;
using IdentityProvider.Client.Authorisation.Requirements;
using Microsoft.AspNetCore.Authorization;

namespace IdentityProvider.Client.Authorisation.Handlers
{
    public class LOAHandler : AuthorizationHandler<LOARequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, LOARequirement requirement)
        {            
            // Get the AMR claim
            Claim? amrRaw = context.User.FindFirst(c => c.Type == "AMR");

            // No claim then fail
            if (amrRaw is null)
            {
                return Task.CompletedTask;
            }

            // Does the LOA Level in the token exceed or equal what is required?
            int amrLevel = int.Parse(amrRaw.Value.Replace("Level", String.Empty));
            if (amrLevel >= requirement.Level)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
