using System.Security.Claims;
using IdentityProvider.Client.Authorisation.Requirements;
using Microsoft.AspNetCore.Authorization;

namespace IdentityProvider.Client.Authorisation.Handlers;

public class LOAHandler : AuthorizationHandler<LOARequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, LOARequirement requirement)
    {
        switch (requirement.PolicyType.ToLower())
        {
            case "level":

                // Get the AMR claim
                Claim? acrRaw = context.User.FindFirst(c => c.Type.ToLower() == "http://schemas.microsoft.com/claims/authnclassreference"); // Also a constant in Microsoft.Identity.Web but wasn't ready to add all that in just for this

                // No claim then fail
                if (acrRaw is null)
                {
                    return Task.CompletedTask;
                }

                // Does the LOA Level in the token exceed or equal what is required?
                int acrLevel = int.Parse(acrRaw.Value.Replace("Level", String.Empty, StringComparison.OrdinalIgnoreCase));
                int requirementLevel = int.Parse(requirement.PolicyValue);
                if (acrLevel >= requirementLevel)
                    context.Succeed(requirement);
                else
                {
#warning TODO: Implement step up response message here
                    context.Fail(new AuthorizationFailureReason(this, "Step up required, too low an ACR Level for this resource"));
                }

                break;

            case "scope":

                // If the scopes are comma seperated then split and trim (if any one matches its a match becasue policies stack anyway)
                String[] scopeMatches = requirement.PolicyValue.Split(",").Select(p => p.Trim()).ToArray();

                // Does one the possible required scopes exist for this user context?
                Claim? scopeRaw = context.User.FindFirst(c => scopeMatches.Contains(c.Type, StringComparer.OrdinalIgnoreCase));

                // No claim then fail
                if (!(scopeRaw is null))
                    context.Succeed(requirement);
                else
                    context.Fail(new AuthorizationFailureReason(this, "Scopes did not match"));

                break;
        }

        return Task.CompletedTask;
    }
}
