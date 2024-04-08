using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Text.Json;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreHandlerFilters;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace AuthServer.Handlers
{
    public static class CustomResponseHandler
    {

        public static OpenIddictServerHandlerDescriptor CustomResponseDescriptor { get; } = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyTokenResponseContext>().AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<CustomProcessJsonResponse>()
                .SetOrder(500_000)
                .SetType(OpenIddictServerHandlerType.Custom)
                .Build();

        public class CustomProcessJsonResponse : IOpenIddictServerHandler<ApplyTokenResponseContext>
        {

            private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

            public CustomProcessJsonResponse(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            {
                _options = options;
            }

            public async ValueTask HandleAsync(ApplyTokenResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Response is not null, "Response is not null");

                var contextResponse = context.Transaction.Response;

                //// mock response 
                //var customResponse = new CustomOpenIddictResponse(contextResponse, "customToken");

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                    throw new InvalidOperationException("Cannot get response");

                context.Logger.LogInformation(nameof(CustomProcessJsonResponse), context.Transaction.Response);

                using var stream = new MemoryStream();
                using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                    Indented = !_options.CurrentValue.SuppressJsonResponseIndentation
                });

                context.Transaction.Response.WriteTo(writer);
                writer.Flush();

                response.ContentLength = stream.Length;
                response.ContentType = "application/json;charset=UTF-8";

                stream.Seek(offset: 0, loc: SeekOrigin.Begin);
                await stream.CopyToAsync(response.Body, 4096, context.CancellationToken);

                context.HandleRequest();
            }
        }
    }
}
