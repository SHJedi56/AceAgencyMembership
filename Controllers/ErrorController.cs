using Microsoft.AspNetCore.Mvc;

namespace AceAgencyMembership.Controllers
{
    public class ErrorController : Controller
    {
        public IActionResult Index()
        {
            return View("Error"); // Generic error view
        }

        [Route("Home/Error/{statusCode}")]
        public IActionResult HandleError(int statusCode)
        {
            switch (statusCode)
            {
                case 404:
                    return View("Error404"); // Custom 404 view
                case 403:
                    return View("Error403"); // Custom 403 view
                default:
                    return View("Error"); // Generic error view
            }
        }
    }
}
