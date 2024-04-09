using AuthServer.Entities;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers.Protection;

namespace AuthServer.Handlers
{
    public static class TestTokenValidationHandler
    {
        public static OpenIddictValidationHandlerDescriptor ValidateTokenDescriptor { get; } = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>().UseScopedHandler<ValidateCustomJsonWebToken>().SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500)
        .SetType(OpenIddictValidationHandlerType.Custom).Build();

        public static OpenIddictValidationHandlerDescriptor ValidateIdentityModelTestDescriptor { get; } = OpenIddictValidationHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidateIdentityModelToken>()
                    .SetOrder(ValidateReferenceTokenIdentifier.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

        #region Check and validate custom token and then extract identifier and pull token from token Manager
        public class ValidateCustomJsonWebToken : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            private readonly IOpenIddictTokenManager _tokenManager;
            private readonly IConfiguration _configuration;

            public ValidateCustomJsonWebToken(IOpenIddictTokenManager tokenManager, IConfiguration configuration)
            {
                _tokenManager = tokenManager;
                _configuration = configuration;
            }

            public async ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("no context");
                }
                if (context.IsRequestHandled || context.IsRequestSkipped || context.IsRejected)
                {
                    return;
                }
                var token = context.Token;
                if(token == null)
                {
                    throw new InvalidOperationException("No Token is found");
                }

                // perform checking && some custom token validation
                var tokenHandler = new JwtSecurityTokenHandler();
                var tokenSecret = _configuration.GetSection("TokenConfig:Secret").Get<string>();
                var key = Encoding.UTF8.GetBytes(tokenSecret);

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = false,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var identifier = jwtToken.Claims.First(x => x.Type == "id").Value;

                //end
                var customToken = await _tokenManager.FindByIdAsync(identifier);

                if (customToken is CustomToken ct)
                {
                    context.Token = ct.Token;
                }

                context.Logger.LogTrace(nameof(ValidateCustomJsonWebToken));
            }
        }
        #endregion
    }
}
