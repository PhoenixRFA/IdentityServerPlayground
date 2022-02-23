using Duende.IdentityServer;
using Duende.IdentityServer.Validation;

namespace IdentityServer
{
    public class TestBackchannelAuthenticationUserValidator : IBackchannelAuthenticationUserValidator
    {
        public Task<BackchannelAuthenticationUserValidatonResult> ValidateRequestAsync(BackchannelAuthenticationUserValidatorContext userValidatorContext)
        {
            
            var isuser = new IdentityServerUser("1")
            {
                DisplayName = "Bob"
            };

            var res = new BackchannelAuthenticationUserValidatonResult
            {
                //Subject = isuser.CreatePrincipal()
                Error = "some_error"
            };

            return Task.FromResult(res);
        }
    }
}
