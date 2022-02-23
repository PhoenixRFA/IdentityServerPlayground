using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;

namespace IdentityServer
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            };

        public static IEnumerable<ApiResource> ApiResources =>
            new ApiResource[]
            {
            new ApiResource("api1")
            {
                DisplayName = "API 1",
                ApiSecrets = { new Secret("secret".Sha256()) },
                Scopes = new [] { "openid", "scope3" },
            }
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
            new ApiScope("scope1"),
            new ApiScope("scope2"),
            new ApiScope("scope3"),
            new ApiScope("testScope")
            };

        public static IEnumerable<Client> Clients =>
            new Client[]
            {
            // m2m client credentials flow client
            new Client
            {
                ClientId = "m2m.client",
                ClientName = "Client Credentials Client",

                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = { new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256()) },

                AllowedScopes = { "scope1" }
            },
            new Client
            {
                ClientId = "m2m.client.jwt",
                
                ClientSecrets = {
                    new Secret
                    {
                        Type = IdentityServerConstants.SecretTypes.JsonWebKey,
                        Value = RSAjwkForDemo.PublicKey
                    }
                    },
                AllowedGrantTypes = GrantTypes.ClientCredentials,

                AllowedScopes = { "scope1" }
            },

            new Client
            {
                ClientId = "spa.client",
                ClientName = "JavaScript Credentials Client",
                RequireClientSecret = false,

                AllowedGrantTypes = GrantTypes.Code,

                RedirectUris = { "https://localhost:5003/?mode=default" },
                PostLogoutRedirectUris = { "https://localhost:5003/" },
                AllowedCorsOrigins = { "https://localhost:5003" },

                AllowedScopes = { "openid", "scope3" },
                AllowOfflineAccess = true,
                RefreshTokenExpiration = TokenExpiration.Absolute,
                RefreshTokenUsage = TokenUsage.OneTimeOnly,

                RequireConsent = true
            },

            new Client
            {
                ClientId = "spa.client.referenceToken",
                ClientName = "JavaScript Credentials Client with Reference token",
                RequireClientSecret = false,

                AllowedGrantTypes = GrantTypes.Code,
                AccessTokenType = AccessTokenType.Reference,

                RedirectUris = { "https://localhost:5003/?mode=ref_token" },
                PostLogoutRedirectUris = { "https://localhost:5003/" },
                AllowedCorsOrigins = { "https://localhost:5003" },

                AllowedScopes = { "openid", "scope3" }
            },

            new Client
            {
                ClientId = "ciba.client",
                ClientName = "CIBA client",
                ClientSecrets = { new Secret("D6AD724F-070D-4CCA-96D0-279E5D42B271".Sha256()) },

                AllowedGrantTypes = GrantTypes.Ciba,
                RequireConsent = true,
                AllowOfflineAccess = true,
                AllowedScopes = { "openid", "profile", "scope2" }
            },

            new Client
            {
                ClientId = "tokenExchange.client",
                ClientName = "Token Exchange Client",
                ClientSecrets = { new Secret("7E42CFD4-D8D4-4F96-A416-0BE336B2A82A".Sha256()) },
                AllowedGrantTypes = { OidcConstants.GrantTypes.TokenExchange },

                AllowedScopes = { "scope2" }
            },

            // interactive client using code flow + pkce
            new Client
            {
                ClientId = "interactive",
                ClientSecrets = { new Secret("49C1A7E1-0C79-4A89-A3D6-A37998FB86B0".Sha256()) },

                AllowedGrantTypes = GrantTypes.Code,

                RedirectUris = { "https://localhost:44300/signin-oidc" },
                FrontChannelLogoutUri = "https://localhost:44300/signout-oidc",
                PostLogoutRedirectUris = { "https://localhost:44300/signout-callback-oidc" },

                AllowOfflineAccess = true,
                AllowedScopes = { "openid", "profile", "scope2" }
            },
            };
    }
}