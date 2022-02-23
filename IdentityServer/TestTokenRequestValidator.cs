using Duende.IdentityServer.Validation;
using System.Security.Claims;

namespace IdentityServer
{
    public class TestTokenRequestValidator : ICustomTokenRequestValidator
    {
        public Task ValidateAsync(CustomTokenRequestValidationContext context)
        {
            context.Result.ValidatedRequest.ClientClaims.Add(new Claim("tst", "test"));
            context.Result.ValidatedRequest.ValidatedResources.ParsedScopes.Add(new ParsedScopeValue("res_test", "res_test", "res_test"));

            return Task.CompletedTask;
        }
    }
}
