using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace okta_dotnet_saml.Controllers
{
    [Route("account")]
    public class AccountController : Controller
    {
        private const string REDIRECT_URL = "https://fast.okta.com/app/fasttechnology_oktadotnetsaml_1/exk1m1hhntCbsCO0H2p7/sso/saml";

        [HttpGet("login")]
        public IActionResult Login() => Redirect(RedirectUrl());

        [HttpGet("logout")]
        public IActionResult Logout() => Redirect(RedirectUrl());

        private string RedirectUrl() => REDIRECT_URL;

        [HttpPost("/samlACS")]
        public IActionResult SamlACS([FromForm] string samlResponse)
        {
            Console.Write(samlResponse);
            X509Store store = new X509Store(StoreName.TrustedPublisher ,StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = store.Certificates.Find(X509FindType.FindByIssuerName, "okta", false);
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