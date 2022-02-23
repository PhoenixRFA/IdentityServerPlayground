using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using IdentityModel;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace IdentityServer
{
    public class TokenExchangeGrantValidator : IExtensionGrantValidator
    {
        public string GrantType => OidcConstants.GrantTypes.TokenExchange;
        private readonly ITokenValidator _validator;

        public TokenExchangeGrantValidator(ITokenValidator validator)
        {
            _validator = validator;
        }

        public async Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidRequest);

            var customResponse = new Dictionary<string, object>
            {
                { OidcConstants.TokenResponse.IssuedTokenType, OidcConstants.TokenTypeIdentifiers.AccessToken }
            };

            //incoming token
            string subjectToken = context.Request.Raw.Get(OidcConstants.TokenRequest.SubjectToken);
            string subjectTokenType = context.Request.Raw.Get(OidcConstants.TokenRequest.SubjectTokenType);

            if(string.IsNullOrEmpty(subjectToken)) return;
            if(subjectTokenType != OidcConstants.TokenTypeIdentifiers.AccessToken) return;

            TokenValidationResult validateResult = await _validator.ValidateAccessTokenAsync(subjectToken);
            if(validateResult.IsError) return;

            string sub = validateResult.Claims.First(x => x.Type == JwtClaimTypes.Subject).Value;
            string clientId = validateResult.Claims.First(x=>x.Type == JwtClaimTypes.ClientId).Value;

            string style = context.Request.Raw.Get("exchange_style");

            switch (style)
            {
                case "impersonation":
                    // set token client_id to original id?
                    context.Request.ClientId = clientId;
                    context.Result = new GrantValidationResult(
                        subject: sub,
                        authenticationMethod: GrantType,
                        customResponse: customResponse
                        );
                    break;
                case "delegation":
                    //set token client_id to original id
                    context.Request.ClientId = clientId;

                    var actor = new { client_id = context.Request.Client.ClientId };
                    var actClaim = new Claim(JwtClaimTypes.Actor, JsonSerializer.Serialize(actor), "json");

                    context.Result = new GrantValidationResult(
                        subject: sub,
                        authenticationMethod: GrantType,
                        claims: new[] { actClaim },
                        customResponse: customResponse
                        );
                    break;
                case "custom":
                    context.Result = new GrantValidationResult(
                        subject: sub,
                        authenticationMethod: GrantType,
                        customResponse: customResponse
                        );
                    break;
                default:
                    break;
            }
        }
    }
}
