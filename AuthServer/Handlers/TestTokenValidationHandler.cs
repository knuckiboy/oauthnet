using AuthServer.Entities;
using AuthServer.Services;
using OpenIddict.Validation;
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
            private readonly TestTokenService _testTokenService;

            public ValidateCustomJsonWebToken(TestTokenService testTokenService)
            {
                _testTokenService = testTokenService;
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
                if (token == null)
                {
                    throw new InvalidOperationException("No Token is found");
                }
                try
                {

                    // perform checking && some custom token validation
                    _testTokenService.ValidateToken(token, out var tokenMap);

                    if (tokenMap.CustomToken is CustomToken ct)
                    {
                        context.Token = ct.Token;
                    }
                }
                catch (Exception ex)
                {
                    context.Logger.LogError(ex.ToString());
                    throw;
                }

                context.Logger.LogTrace(nameof(ValidateCustomJsonWebToken));
            }
        }
        #endregion

    }
}
