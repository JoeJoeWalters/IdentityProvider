using IdentityProvider.Client.Authorisation.Handlers;
using IdentityProvider.Client.Authorisation.Policies;
using IdentityProvider.Common.Contracts;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace IdentityProvider.Client.Authentication
{
    public static class Extensions
    {
        public static WebApplication? UseAuthNAuthZ(this WebApplication? app)
        {
            app.UseAuthentication();
            app.UseAuthorization();

            return app;
        }

        public static IServiceCollection AddAuthNAuthZ(this IServiceCollection services)
        {
            var publicKey = File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "keys", "public.pem"), Encoding.UTF8);
            RSA imported = RSA.Create();
            imported.ImportFromPem(publicKey);
            RSAParameters rsaProperties = imported.ExportParameters(false);

            // Add LOA Level Authorisation
            // https://docs.microsoft.com/en-us/aspnet/core/security/authentication/policyschemes?view=aspnetcore-6.0
            // https://docs.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-6.0
            // https://docs.microsoft.com/en-us/aspnet/core/security/authorization/limitingidentitybyscheme?view=aspnetcore-6.0
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.SaveToken = true;
                    jwtOptions.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateIssuerSigningKey = false,
                        ValidAudiences = new List<String>() { Audiences.SystemA, Audiences.SystemB },
                        ValidIssuers = new List<string>() { Issuers.PrimaryIssuer },
                        IssuerSigningKey = new RsaSecurityKey(rsaProperties) //Encoding.UTF8.GetBytes(publicKey))
                    };
                });

            // Policies for authorisation picked up from the registered singletons
            services.AddSingleton<IAuthorizationHandler, LOAHandler>();
            services.AddSingleton<IAuthorizationPolicyProvider, LOAPolicyProvider>();
            services.AddAuthorization();

            return services;
        }
    }
}
