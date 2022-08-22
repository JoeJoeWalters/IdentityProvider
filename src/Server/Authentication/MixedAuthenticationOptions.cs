using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Text;

namespace IdentityServer.Server.Authentication
{
    public class MixedAuthenticationOptions : AuthenticationSchemeOptions
    {
        public Boolean SaveTokens { get; set; } = true;
    }
}
