using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Server.Authentication;
using Server.Services;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Security.Cryptography;
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

            // Map the server settings from configuration before loading the signing keys to it seperately
            ServerSettings settings = builder.Configuration.GetSection("SecurityKeys").Get<ServerSettings>();
            if (settings != null)
            {
                // Create somewhere for tokens to be stored and retrieved later if needed
                ITokenStorage tokenStorage = new TokenStorage();
                builder.Services.AddSingleton<ITokenStorage>(tokenStorage);

                // Create services for comparison and hashing
                IHashService hashService = new HashService();
                builder.Services.AddSingleton<IHashService>(hashService);

                IPasscodeService pinService = new PasscodeService(hashService);
                builder.Services.AddSingleton<IPasscodeService>(pinService);

                IOTPService otpService = new MockOTPService();
                builder.Services.AddSingleton<IOTPService>(otpService);

                // Add the private and public keys for signing to the settings collection before adding for DI
                settings.PrivateKey = File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "keys", "private.pem"), Encoding.UTF8);
                settings.PublicKey = File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "keys", "public.pem"), Encoding.UTF8);
                builder.Services.AddSingleton<ServerSettings>(settings);

                // Load the default users and client registrations from the json file
                string path = Path.Combine(Environment.CurrentDirectory, "users.json");
                using (FileStream accessControlStream = File.OpenRead(path))
                {
                    // Generate the signing credentials and create a singleton so they can be used by the dependent services via DI
                    RSA rsa = RSA.Create();
                    rsa.ImportFromPem(settings.PrivateKey.ToCharArray());
                    SigningCredentials signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest)
                    {
                        CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                    };
                    builder.Services.AddSingleton<SigningCredentials>(signingCredentials);

                    // Set up the authentication service consuming the signing credentials and server settings to generate the tokens
                    IAuthenticator authenticator = new Authenticator(new TokenValidationParameters()
                                                                {
                                                                    ValidateLifetime = true,
                                                                    ValidateAudience = true,
                                                                    ValidateIssuer = true,
                                                                    ValidIssuer = settings.Issuer,
                                                                    ValidAudiences = settings.Audiences.Select(aud => aud.Name)
                                                                }, 
                                                                signingCredentials,
                                                                settings,
                                                                hashService,
                                                                pinService,
                                                                tokenStorage);
                    authenticator.RefreshAccessList(accessControlStream); // Pass the user / client registrations file to the authenticator to pre-load them
                    builder.Services.AddSingleton<IAuthenticator>(authenticator);
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
