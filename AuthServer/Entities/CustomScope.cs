using OpenIddict.EntityFrameworkCore.Models;

namespace AuthServer.Entities
{
    public class CustomScope : OpenIddictEntityFrameworkCoreScope<Guid>
    {
        public string? CustomProperty { get; set; }
    }
}
