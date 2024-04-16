using AuthServer.Entities;
using AuthServer.Services;
using OpenIddict.Validation;
using static OpenIddict.Abstractions.OpenIddictConstants;
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
                    .SetType(OpenIddictValidationHandlerType.Custom)
                    .Build();

        #region Check and validate custom token and then extract identifier and pull token from token Manager
        public class ValidateCustomJsonWebToken : IOpenIddictValidationHandler<ValidateTokenContext>
        {
            private readonly TestTokenService _testTokenService;

            public ValidateCustomJsonWebToken(TestTokenService testTokenService)
            {
                _testTokenService = testTokenService;
            }

            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException("no context");
                }
                if (context.IsRequestHandled || context.IsRequestSkipped || context.IsRejected)
                {
                    return ValueTask.CompletedTask;
                }
                var token = context.Token;
                if (token == null)
                {
                    context.Reject(
                        error: Errors.MissingToken, "Missing Token");

                    return ValueTask.CompletedTask;
                }
                try
                {

                    // perform checking && some custom token validation
                    var isValid = _testTokenService.ValidateToken(token, out var tokenMap);
                    if (!isValid)
                    {
                        context.Reject(
                         error: Errors.InvalidToken, "Invalid Token");

                        return ValueTask.CompletedTask;
                    }
                    if (tokenMap.AccessToken is CustomToken ct)
                    {
                        context.Token = ct.Token;
                    }
                }
                catch (Exception ex)
                {
                    context.Logger.LogError(ex.ToString());
                    context.Reject(
                        error: Errors.InvalidRequest, ex.Message);

                    return ValueTask.CompletedTask;
                }

                context.Logger.LogTrace(nameof(ValidateCustomJsonWebToken));
                return ValueTask.CompletedTask;
            }
        }
        #endregion

    }
}
