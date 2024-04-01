using OpenIddict.EntityFrameworkCore.Models;

namespace AuthServer.Entities
{
    public class CustomToken : OpenIddictEntityFrameworkCoreToken<Guid, CustomApplication, CustomAuthorization>
    {
        public string? CustomMessage { get; set; }
    }
}
