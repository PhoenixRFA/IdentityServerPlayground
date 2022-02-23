using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;

namespace IdentityServer.CibaServices
{
    public class ConsoleBackchannelAuthenticationUserNotificationService : IBackchannelAuthenticationUserNotificationService
    {
        private ILogger<ConsoleBackchannelAuthenticationUserNotificationService> _logger;

        public ConsoleBackchannelAuthenticationUserNotificationService(ILogger<ConsoleBackchannelAuthenticationUserNotificationService> logger)
        {
            _logger = logger;
        }

        public Task SendLoginRequestAsync(BackchannelUserLoginRequest request)
        {
            _logger.LogInformation("CIBA request: {id}", request.InternalId);

            return Task.CompletedTask;
        }
    }
}
