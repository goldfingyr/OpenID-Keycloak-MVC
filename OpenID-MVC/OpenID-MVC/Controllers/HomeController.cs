﻿using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using OpenID_MVC.Models;

namespace OpenID_MVC.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            //Debug this line of code if you want to validate the content jwt.io
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        /*
         * Instead of policy based authorization you can use roles directly.
         * Remember to change accordingly in startup.cs
         * They need to be named excatly like the roles you have defined, in your keycloak client
         * Example:
         * [Authorize(Roles = "admin,user")]
         * [Authorize(Roles = "admin")]
         * [Authorize(Roles = "user")]
         * 
         * If nothing works, try to test just with [Authorize] to see that you can get a token from your keycloak
         */

        //[Authorize(Policy = "admins")]
        [Authorize(Roles = "admin")]
        public IActionResult AuthenticationAdmin()
        {
            var accessToken = HttpContext.GetTokenAsync("access_token").Result;
            using (HttpClient client = new HttpClient())
            {
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:7000/WeatherForecast");
                //HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "http://localhost:7001/WeatherForecast");
                //HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, "http://l2.ucnit.eu:7000/WeatherForecast");
                request.Headers.Add("Authorization", "Bearer " + accessToken);
                using (var response = client.SendAsync(request).Result)
                {
                    try
                    {
                        response.EnsureSuccessStatusCode();
                        string apiResponse = response.Content.ReadAsStringAsync().Result;
                    }
                    catch (HttpRequestException ex)
                    {
                    }

                }
            }
            //Debug this line of code if you want to validate the content jwt.io
            return View();
        }

        [Authorize(Policy = "noaccess")]
        public IActionResult AuthenticationNoAccess()
        {
            //Test that your identity does not have this claim attaced
            //Debug this line of code if you want to validate the content jwt.io
            return View();
        }

        //A policy was defined, so authorize must use a policy instead of a role.
        //[Authorize(Policy = "users")]
        [Authorize(Roles ="user")]
        public async Task<IActionResult> AuthenticationAsync()
        {

            //Find claims for the current user
            ClaimsPrincipal currentUser = this.User;
            //Get username, for keycloak you need to regex this to get the clean username
            var currentUserName = currentUser.FindFirst(ClaimTypes.NameIdentifier).Value;
            //logs an error so it's easier to find - thanks debug.
            _logger.LogError(currentUserName);

            //Debug this line of code if you want to validate the content jwt.io
            string accessToken = await HttpContext.GetTokenAsync("access_token");
            string idToken = await HttpContext.GetTokenAsync("id_token");
            string refreshToken = await HttpContext.GetTokenAsync("refresh_token");


            /*
             * Token exchange implementation
             * Uncomment section below
             */
            /*
            //Call a token exchange to call another service in keycloak
            //Remember to implement a logger with the default constructor for more visibility
            TokenExchange exchange = new TokenExchange();
            //Do a refresh token, if the service you need to call has a short lived token time
            var newAccessToken = await exchange.GetRefreshTokenAsync(refreshToken);
            var serviceAccessToken = await exchange.GetTokenExchangeAsync(newAccessToken);
            //Use the access token to call the service that exchanged the token
            //Example:
            // MyService myService = new MyService/();
            //var myService = await myService.GetDataAboutSomethingAsync(serviceAccessToken):
            */

            //Get all claims for roles that you have been granted access to 
            IEnumerable<Claim> roleClaims = User.FindAll(ClaimTypes.Role);
            IEnumerable<string> roles = roleClaims.Select(r => r.Value);
            foreach (var role in roles)
            {
                _logger.LogError(role);
            }

            //Another way to display all role claims
            var currentClaims = currentUser.FindAll(ClaimTypes.Role).ToList();
            foreach (var claim in currentClaims)
            {
                _logger.LogError(claim.ToString());
            }

            return View();
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