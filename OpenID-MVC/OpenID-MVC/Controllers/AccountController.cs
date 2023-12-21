using Microsoft.AspNetCore.Mvc;

namespace OpenID_MVC.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
