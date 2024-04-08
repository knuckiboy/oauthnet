using OpenIddict.EntityFrameworkCore.Models;

namespace AuthServer.Entities
{
    public class CustomToken : OpenIddictEntityFrameworkCoreToken<Guid, CustomApplication, CustomAuthorization>
    {
        public string? CustomMessage { get; set; }
        // TODO: explore storing it in another table?
        // TODO: explore storing custom token?
        public string? Token { get; set; }

    }
}
