using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Stores;
using Duende.IdentityServer.Validation;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace IdentityServer.TokenExchange
{
    internal class TokenValidator : ITokenValidator
    {
        private readonly ILogger _logger;
        private readonly IdentityServerOptions _options;
        private readonly IHttpContextAccessor _context;
        private readonly IReferenceTokenStore _referenceTokenStore;
        private readonly ICustomTokenValidator _customValidator;
        private readonly IClientStore _clients;
        private readonly IProfileService _profile;
        private readonly IKeyMaterialService _keys;
        private readonly ISystemClock _clock;

        public TokenValidator(
            IdentityServerOptions options,
            IHttpContextAccessor context,
            IClientStore clients,
            IProfileService profile,
            IReferenceTokenStore referenceTokenStore,
            IRefreshTokenStore refreshTokenStore,
            ICustomTokenValidator customValidator,
            IKeyMaterialService keys,
            ISystemClock clock,
            ILogger<TokenValidator> logger)
        {
            _options = options;
            _context = context;
            _clients = clients;
            _profile = profile;
            _referenceTokenStore = referenceTokenStore;
            _customValidator = customValidator;
            _keys = keys;
            _clock = clock;
            _logger = logger;
        }

        public async Task<Duende.IdentityServer.Validation.TokenValidationResult> ValidateIdentityTokenAsync(string token, string clientId = null, bool validateLifetime = true)
        {
            _logger.LogDebug("Start identity token validation");

            if (token.Length > _options.InputLengthRestrictions.Jwt)
            {
                _logger.LogError("JWT too long");
                return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                clientId = GetClientIdFromJwt(token);

                if (string.IsNullOrWhiteSpace(clientId))
                {
                    _logger.LogError("No clientId supplied, can't find id in identity token.");
                    return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
                }
            }

            var client = await _clients.FindEnabledClientByIdAsync(clientId);
            if (client == null)
            {
                _logger.LogError("Unknown or disabled client: {clientId}.", clientId);
                return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }

            _logger.LogDebug("Client found: {clientId} / {clientName}", client.ClientId, client.ClientName);

            var keys = await _keys.GetValidationKeysAsync();
            var result = await ValidateJwtAsync(token, keys, audience: clientId, validateLifetime: validateLifetime);

            result.Client = client;

            if (result.IsError)
            {
                return result;
            }

            _logger.LogDebug("Calling into custom token validator: {type}", _customValidator.GetType().FullName);
            var customResult = await _customValidator.ValidateIdentityTokenAsync(result);

            if (customResult.IsError)
            {
                return customResult;
            }

            return customResult;
        }

        public async Task<Duende.IdentityServer.Validation.TokenValidationResult> ValidateAccessTokenAsync(string token, string expectedScope = null)
        {
            _logger.LogTrace("Start access token validation");

            Duende.IdentityServer.Validation.TokenValidationResult result;

            if (token.Contains("."))
            {
                if (token.Length > _options.InputLengthRestrictions.Jwt)
                {
                    _logger.LogError("JWT too long");

                    return new Duende.IdentityServer.Validation.TokenValidationResult
                    {
                        IsError = true,
                        Error = OidcConstants.ProtectedResourceErrors.InvalidToken,
                        ErrorDescription = "Token too long"
                    };
                }

                result = await ValidateJwtAsync(
                    token,
                    await _keys.GetValidationKeysAsync());
            }
            else
            {
                if (token.Length > _options.InputLengthRestrictions.TokenHandle)
                {
                    _logger.LogError("token handle too long");

                    return new Duende.IdentityServer.Validation.TokenValidationResult
                    {
                        IsError = true,
                        Error = OidcConstants.ProtectedResourceErrors.InvalidToken,
                        ErrorDescription = "Token too long"
                    };
                }

                result = await ValidateReferenceAccessTokenAsync(token);
            }

            if (result.IsError)
            {
                return result;
            }

            // make sure client is still active (if client_id claim is present)
            var clientClaim = result.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.ClientId);
            if (clientClaim != null)
            {
                var client = await _clients.FindEnabledClientByIdAsync(clientClaim.Value);
                if (client == null)
                {
                    _logger.LogError("Client deleted or disabled: {clientId}", clientClaim.Value);

                    result.IsError = true;
                    result.Error = OidcConstants.ProtectedResourceErrors.InvalidToken;
                    result.Claims = null;

                    return result;
                }
            }

            // make sure user is still active (if sub claim is present)
            var subClaim = result.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject);
            if (subClaim != null)
            {
                var principal = Principal.Create("tokenvalidator", result.Claims.ToArray());

                if (!string.IsNullOrWhiteSpace(result.ReferenceTokenId))
                {
                    principal.Identities.First().AddClaim(new Claim(JwtClaimTypes.ReferenceTokenId, result.ReferenceTokenId));
                }

                var isActiveCtx = new IsActiveContext(principal, result.Client, IdentityServerConstants.ProfileIsActiveCallers.AccessTokenValidation);
                await _profile.IsActiveAsync(isActiveCtx);

                if (isActiveCtx.IsActive == false)
                {
                    _logger.LogError("User marked as not active: {subject}", subClaim.Value);

                    result.IsError = true;
                    result.Error = OidcConstants.ProtectedResourceErrors.InvalidToken;
                    result.Claims = null;

                    return result;
                }
            }

            // check expected scope(s)
            if (!string.IsNullOrWhiteSpace(expectedScope))
            {
                var scope = result.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Scope && c.Value == expectedScope);
                if (scope == null)
                {
                    return Invalid(OidcConstants.ProtectedResourceErrors.InsufficientScope);
                }
            }

            _logger.LogDebug("Calling into custom token validator: {type}", _customValidator.GetType().FullName);
            var customResult = await _customValidator.ValidateAccessTokenAsync(result);

            if (customResult.IsError)
            {
                return customResult;
            }

            return customResult;
        }

        private async Task<Duende.IdentityServer.Validation.TokenValidationResult> ValidateJwtAsync(string jwt, IEnumerable<SecurityKeyInfo> validationKeys, bool validateLifetime = true, string audience = null)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = _context.HttpContext.GetIdentityServerIssuerUri(),
                IssuerSigningKeys = validationKeys.Select(k => k.Key),
                ValidateLifetime = validateLifetime
            };

            if (!string.IsNullOrWhiteSpace(audience))
            {
                parameters.ValidAudience = audience;
            }
            else
            {
                parameters.ValidateAudience = false;
            }

            try
            {
                var id = handler.ValidateToken(jwt, parameters, out var securityToken);
                var jwtSecurityToken = securityToken as JwtSecurityToken;

                // if no audience is specified, we make at least sure that it is an access token
                if (string.IsNullOrWhiteSpace(audience))
                {
                    if (string.IsNullOrWhiteSpace(_options.AccessTokenJwtType))
                    {
                        var type = jwtSecurityToken.Header.Typ;
                        if (!string.Equals(type, _options.AccessTokenJwtType))
                        {
                            return new Duende.IdentityServer.Validation.TokenValidationResult
                            {
                                IsError = true,
                                Error = "invalid JWT token type"
                            };
                        }

                    }
                }

                // if access token contains an ID, log it
                var jwtId = id.FindFirst(JwtClaimTypes.JwtId);

                // load the client that belongs to the client_id claim
                Client client = null;
                var clientId = id.FindFirst(JwtClaimTypes.ClientId);
                if (clientId != null)
                {
                    client = await _clients.FindEnabledClientByIdAsync(clientId.Value);
                    if (client == null)
                    {
                        throw new InvalidOperationException("Client does not exist anymore.");
                    }
                }

                var claims = id.Claims.ToList();

                // check the scope format (array vs space delimited string)
                var scopes = claims.Where(c => c.Type == JwtClaimTypes.Scope).ToArray();
                if (scopes.Any())
                {
                    foreach (var scope in scopes)
                    {
                        if (scope.Value.Contains(" "))
                        {
                            claims.Remove(scope);

                            var values = scope.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                            foreach (var value in values)
                            {
                                claims.Add(new Claim(JwtClaimTypes.Scope, value));
                            }
                        }
                    }
                }

                return new Duende.IdentityServer.Validation.TokenValidationResult
                {
                    IsError = false,

                    Claims = claims,
                    Client = client,
                    Jwt = jwt
                };
            }
            catch (SecurityTokenExpiredException expiredException)
            {
                _logger.LogInformation(expiredException, "JWT token validation error: {exception}", expiredException.Message);
                return Invalid(OidcConstants.ProtectedResourceErrors.ExpiredToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "JWT token validation error: {exception}", ex.Message);
                return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }
        }

        private async Task<Duende.IdentityServer.Validation.TokenValidationResult> ValidateReferenceAccessTokenAsync(string tokenHandle)
        {
            var token = await _referenceTokenStore.GetReferenceTokenAsync(tokenHandle);

            if (token == null)
            {
                return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }

            if (_clock.UtcNow.UtcDateTime > token.CreationTime.AddSeconds(token.Lifetime))
            {
                await _referenceTokenStore.RemoveReferenceTokenAsync(tokenHandle);
                return Invalid(OidcConstants.ProtectedResourceErrors.ExpiredToken);
            }

            // load the client that is defined in the token
            Client client = null;
            if (token.ClientId != null)
            {
                client = await _clients.FindEnabledClientByIdAsync(token.ClientId);
            }

            if (client == null)
            {
                return Invalid(OidcConstants.ProtectedResourceErrors.InvalidToken);
            }

            return new Duende.IdentityServer.Validation.TokenValidationResult
            {
                IsError = false,

                Client = client,
                Claims = ReferenceTokenToClaims(token),
                ReferenceToken = token,
                ReferenceTokenId = tokenHandle
            };
        }

        private IEnumerable<Claim> ReferenceTokenToClaims(Token token)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Issuer, token.Issuer),
                new Claim(JwtClaimTypes.NotBefore, new DateTimeOffset(token.CreationTime).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtClaimTypes.Expiration, new DateTimeOffset(token.CreationTime).AddSeconds(token.Lifetime).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            foreach (var aud in token.Audiences)
            {
                claims.Add(new Claim(JwtClaimTypes.Audience, aud));
            }

            claims.AddRange(token.Claims);
            return claims;
        }

        private string GetClientIdFromJwt(string token)
        {
            try
            {
                var jwt = new JwtSecurityToken(token);
                var clientId = jwt.Audiences.FirstOrDefault();

                return clientId;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Malformed JWT token: {exception}", ex.Message);
                return null;
            }
        }

        private Duende.IdentityServer.Validation.TokenValidationResult Invalid(string error)
        {
            return new Duende.IdentityServer.Validation.TokenValidationResult
            {
                IsError = true,
                Error = error
            };
        }
    }
}
