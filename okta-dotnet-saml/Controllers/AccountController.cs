using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace okta_dotnet_saml.Controllers
{
    [Route("account")]
    public class AccountController : Controller
    {
        private string REDIRECT_URL;
        private string ISSUER_NAME;
        private StoreName STORE_NAME;
        private StoreLocation STORE_LOCATION;

        public AccountController(IConfiguration configuration)
        {
            IConfigurationSection SAML_sec = configuration.GetSection("SAML");
            REDIRECT_URL = SAML_sec.GetValue(typeof(string), "redirect_url").ToString();
            IConfigurationSection X509_sec = SAML_sec.GetSection("X509");
            STORE_NAME = (StoreName)X509_sec.GetValue(typeof(StoreName), "StoreName");
            ISSUER_NAME = (string)X509_sec.GetValue(typeof(string), "IssuerName");
            STORE_LOCATION = (StoreLocation)X509_sec.GetValue(typeof(StoreLocation), "StoreLocation");
        }


        [HttpGet("login")]
        public IActionResult Login() => Redirect(RedirectUrl());

        [HttpGet("logout")]
        public IActionResult Logout() => Redirect(RedirectUrl());

        private string RedirectUrl() => REDIRECT_URL;

        [HttpPost("/samlACS")]
        public IActionResult SamlACS([FromForm] string samlResponse)
        {
            Console.Write(samlResponse);
            X509Store store = new X509Store(STORE_NAME, STORE_LOCATION);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = store.Certificates.Find(X509FindType.FindByIssuerName, ISSUER_NAME, false);
            X509Certificate2 oktaCert = certCollection[0];
            store.Close();


            samlResponse = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponse));
            /*
             * if(saml response is successful)
             * {
             *      set cookie
             *      redirect to home url
             * }
             * 
             * return Redirect(OKTA sign in URL)
             * **/
            return Ok(samlResponse);
        }
    }
}