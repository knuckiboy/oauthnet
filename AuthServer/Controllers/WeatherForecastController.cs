using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace AuthServer.Controllers
{

    public class WeatherForecastController : Controller
    {
        private static readonly string[] Summaries = new[]
        {
       "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"

        };

        [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("weather")]
        public IActionResult Index()
        {
            return Ok(Summaries);
        }
    }
}
