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

            builder.Services.AddCors();

            ServerSettings settings = builder.Configuration.GetSection("SecurityKeys").Get<ServerSettings>();
            if (settings != null)
            {
                /*
                string issuer = securityKeys.GetValue<String>("Issuer");
                List<Audience> audiences = securityKeys.GetValue<List<Audience>>("Audiences");
                */

                settings.PrivateKey = File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "keys", "private.pem"), Encoding.UTF8);
                settings.PublicKey = File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "keys", "public.pem"), Encoding.UTF8);

                builder.Services.AddSingleton<ServerSettings>(settings);

                string path = Path.Combine(Environment.CurrentDirectory, "users.json");
                using (FileStream accessControlStream = File.OpenRead(path))
                {
                    // Set up the authentication service with the appropriate authenticator implementation
                    IUserAuthenticator userAuthenticator = new UserAuthenticator(
                                                                new TokenValidationParameters()
                                                                {
                                                                    ValidateLifetime = true,
                                                                    ValidateAudience = true,
                                                                    ValidateIssuer = true,
                                                                    ValidIssuer = settings.Issuer,
                                                                    ValidAudiences = settings.Audiences.Select(aud => aud.Name)
                                                                });

                    userAuthenticator.RefreshAccessList(accessControlStream);
                    builder.Services.AddSingleton<IUserAuthenticator>(userAuthenticator);
                }

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
                    options.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());

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

            builder.Services.AddMvc();
            builder.Services
                .AddRazorPages()
                .AddRazorRuntimeCompilation();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.UseRouting();

            app.MapControllers();

            app.MapRazorPages();

            app.UseStaticFiles();

            // global cors policy
            app.UseCors(x => x
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader());

            app.Run();
        }
    }
}
