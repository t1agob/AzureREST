using AzureREST.web.Models;
using AzureREST.web.Models.Azure;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Caching;
using System.Web.Mvc;

namespace AzureREST.web.Controllers
{
    public class AzureController : Controller
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string appKey = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenantId = ConfigurationManager.AppSettings["ida:TenantId"];
        private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

        public static readonly string Authority = aadInstance + tenantId;
        // This is the resource ID of the AAD Graph API.  We'll need this to request a token to call the Graph API.
        //string graphResourceId = "https://graph.windows.net/";
        string ResourceId = "https://management.azure.com/";
        string AccessToken = null;

        [Authorize]
        // GET: Azure
        public async Task<ActionResult> Index()
        {
            return View();
        }

        [Authorize]
        private async Task GetAccessToken()
        {
            var signedInUser = Convert.ToBase64String(Encoding.UTF8.GetBytes(User.Identity.Name));

            var ac = new AuthenticationContext(Authority, new ADALTokenCache(signedInUser));
            AuthenticationResult result = null;
            AccessToken = null;

            try
            {
                result = await ac.AcquireTokenSilentAsync(ResourceId, clientId);
                AccessToken = result.AccessToken;
            }
            catch (AdalException adalException)
            {
                if (adalException.ErrorCode == AdalError.FailedToAcquireTokenSilently
                    || adalException.ErrorCode == AdalError.InteractionRequired)
                {
                    var clientCred = new ClientCredential(clientId, appKey);
                    result = await ac.AcquireTokenAsync(ResourceId, clientCred);

                    AccessToken = result.AccessToken;
                }
            }
        }     
        
        [Authorize]
        public async Task<ActionResult> ListSubscriptions()
        {
            List<SubscriptionRM> subscriptionList = null;

            if (AccessToken == null)
            {
                await GetAccessToken();
            }
            
            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {AccessToken}");
                client.DefaultRequestHeaders.Add("Cache-Control", "no-cache");
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                client.BaseAddress = new Uri("https://management.azure.com");

                var response = await client.GetAsync("/subscriptions?api-version=2016-06-01");

                if (!response.IsSuccessStatusCode)
                {
                    throw new UnauthorizedAccessException(response.ReasonPhrase);
                }

                var subscriptions = response.Content.ReadAsStringAsync().Result;
                JToken root = JObject.Parse(subscriptions);
                JToken user = root["value"];
                subscriptionList = JsonConvert.DeserializeObject<List<SubscriptionRM>>(user.ToString());
            }

            return View(subscriptionList);
        }
    }
}