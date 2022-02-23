using Duende.IdentityServer;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using IdentityServer;
using IdentityServer.CibaServices;
using IdentityServer.TokenExchange;
using Microsoft.IdentityModel.Tokens;
using Serilog;

namespace IdentityServer
{
    internal static class HostingExtensions
    {
        public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
        {
            builder.Services.AddRazorPages();

            var isBuilder = builder.Services.AddIdentityServer(options =>
                {
                    options.Events.RaiseErrorEvents = true;
                    options.Events.RaiseInformationEvents = true;
                    options.Events.RaiseFailureEvents = true;
                    options.Events.RaiseSuccessEvents = true;

                // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                options.EmitStaticAudienceClaim = true;
                })
                .AddTestUsers(TestUsers.Users);

            // in-memory, code config
            isBuilder.AddInMemoryIdentityResources(Config.IdentityResources);
            isBuilder.AddInMemoryApiResources(Config.ApiResources);
            isBuilder.AddInMemoryApiScopes(Config.ApiScopes);
            isBuilder.AddInMemoryClients(Config.Clients);

            isBuilder.AddProfileService<ProfileService>();
            isBuilder.AddExtensionGrantValidator<TokenExchangeGrantValidator>();
            isBuilder.AddCustomTokenRequestValidator<TestTokenRequestValidator>();

            isBuilder.AddJwtBearerClientAuthentication();

            builder.Services.AddAuthentication()
                .AddOpenIdConnect("oidc", "Demo IdentityServer", opts =>
                {
                    opts.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    opts.SignOutScheme = IdentityServerConstants.SignoutScheme;
                    opts.SaveTokens = true;

                    opts.Authority = "https://demo.duendesoftware.com";
                    opts.ClientId = "interactive.confidential";
                    opts.ClientSecret = "secret";
                    opts.ResponseType = "code";

                    opts.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        RoleClaimType = "role"
                    };
                });

            //builder.Services.AddTransient<IBackchannelAuthenticationUserValidator, TestBackchannelAuthenticationUserValidator>();
            builder.Services.AddTransient<IBackchannelAuthenticationUserNotificationService, ConsoleBackchannelAuthenticationUserNotificationService>();
            //builder.Services.AddTransient<ITokenValidator, TokenValidator>();
            //builder.Services.AddTransient<ITokenRequestValidator, TokenRequestValidator>();

            return builder.Build();
        }

        public static WebApplication ConfigurePipeline(this WebApplication app)
        {
            app.UseSerilogRequestLogging();

            if (app.Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();
            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();

            app.MapRazorPages()
                .RequireAuthorization();

            return app;
        }
    }
}