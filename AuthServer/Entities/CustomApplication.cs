using OpenIddict.EntityFrameworkCore.Models;

namespace AuthServer.Entities
{
    public class CustomApplication : OpenIddictEntityFrameworkCoreApplication<Guid, CustomAuthorization, CustomToken>
    {
        public string? CustomApp { get; set; }
    }
}
