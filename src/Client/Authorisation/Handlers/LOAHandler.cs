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
            Claim? acrRaw = context.User.FindFirst(c => c.Type.ToLower() == "http://schemas.microsoft.com/claims/authnclassreference"); // Also a constant in Microsoft.Identity.Web but wasn't ready to add all that in just for this

            // No claim then fail
            if (acrRaw is null)
            {
                return Task.CompletedTask;
            }

            // Does the LOA Level in the token exceed or equal what is required?
            int acrLevel = int.Parse(acrRaw.Value.Replace("Level", String.Empty));
            if (acrLevel >= requirement.Level)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
