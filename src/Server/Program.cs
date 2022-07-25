using System.Runtime.CompilerServices;
using System;
using Microsoft.AspNetCore.Mvc.Versioning;
using System.Reflection;
using Microsoft.OpenApi.Models;
using System.Diagnostics.CodeAnalysis;
using Server.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Server
{

    [ExcludeFromCodeCoverage]
    internal class Program
    {
        static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            
            IConfigurationSection securityKeys = builder.Configuration.GetSection("SecurityKeys");
            if (securityKeys != null)
            {
                string JWTKey = securityKeys.GetValue<String>("JWTKey");
                string JWTIssuer = securityKeys.GetValue<String>("JWTIssuer");
                string JWTAudience = securityKeys.GetValue<String>("JWTAudience");

                // Set up the authentication service with the appropriate authenticator implementation
                FileStream accessControl = File.OpenRead(Path.Combine(Environment.CurrentDirectory, "users.json"));
                IUserAuthenticator userAuthenticator = new UserAuthenticator(
                                                            new TokenValidationParameters()
                                                            {
                                                                ValidateLifetime = true,
                                                                ValidateAudience = true,
                                                                ValidateIssuer = true,
                                                                ValidIssuer = JWTIssuer,
                                                                ValidAudience = JWTAudience,
                                                                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWTKey))
                                                            });
                userAuthenticator.RefreshAccessList(accessControl);
                builder.Services.AddSingleton<IUserAuthenticator>(userAuthenticator);
            }

            // API Versioning
            builder.Services.AddApiVersioning(o =>
            {
                o.AssumeDefaultVersionWhenUnspecified = true;
                o.DefaultApiVersion = new Microsoft.AspNetCore.Mvc.ApiVersion(1, 0);
                o.ReportApiVersions = true;
                o.ApiVersionReader = ApiVersionReader.Combine(
                    new QueryStringApiVersionReader("api-version"),
                    new HeaderApiVersionReader("X-Version"),
                    new MediaTypeApiVersionReader("ver"));
            });

            builder.Services.AddVersionedApiExplorer(
                options =>
                {
                    options.GroupNameFormat = "'v'VVV";
                    options.SubstituteApiVersionInUrl = true;
                });

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(
                options =>
                {
                    options.SwaggerDoc("v1", new OpenApiInfo
                    {
                        Version = "v1",
                        Title = "Identity Provider API",
                        Description = "An example Identity Provider",
                        TermsOfService = new Uri("https://example.com/terms"),
                        Contact = new OpenApiContact
                        {
                            Name = "Example Contact",
                            Url = new Uri("https://example.com/contact")
                        },
                        License = new OpenApiLicense
                        {
                            Name = "Example License",
                            Url = new Uri("https://example.com/license")
                        }
                    });

                    var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
                });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
