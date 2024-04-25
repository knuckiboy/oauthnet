using AuthServer.Models;
using AuthServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace AuthServer.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly TestTokenService _testTokenService;


        public HomeController(ILogger<HomeController> logger, TestTokenService testTokenService)
        {
            _logger = logger;
            _testTokenService = testTokenService;
        }

        public async Task<IActionResult> Index()
        {
            var homemodel = new HomeViewModel();
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var username = User.Identity.Name;
            if (User.Identity.IsAuthenticated)
            {
                homemodel.Tokens = await _testTokenService.RetrieveTokensByIdentifier(username);
            }
            return View(homemodel);
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}