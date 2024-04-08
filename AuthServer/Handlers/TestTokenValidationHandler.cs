using AuthServer.Entities;
using OpenIddict.Abstractions;
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
            private readonly IOpenIddictTokenManager _tokenManager;

            public ValidateCustomJsonWebToken(IOpenIddictTokenManager tokenManager)
            {
                _tokenManager = tokenManager;
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
                var identifier = token;
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
