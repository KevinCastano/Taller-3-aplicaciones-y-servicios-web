using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using SampleMvcApp.ViewModels;
using System.Linq;
using System.Security.Claims;
using Auth0.AspNetCore.Authentication;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Text;
using System.Text.Json;


namespace SampleMvcApp.Controllers
{
    public class AccountController : Controller
    {
        public async Task Login(string returnUrl = "/")
        {
            var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
                .WithRedirectUri(returnUrl)
                .Build();

            await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        }

        [Authorize]
        public async Task Logout()
        {
            var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                // Indicate here where Auth0 should redirect the user after a logout.
                // Note that the resulting absolute Uri must be whitelisted in 
                .WithRedirectUri(Url.Action("Index", "Home"))
                .Build();

            await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        [Authorize]
        public IActionResult Profile()
        {
            return View(new UserProfileViewModel()
            {
                Name = User.Identity.Name,
                EmailAddress = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                ProfileImage = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value
            });
        }


        /// <summary>
        /// This is just a helper action to enable you to easily see all claims related to a user. It helps when debugging your
        /// application to see the in claims populated from the Auth0 ID Token
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Claims()
        {
            return View();
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        [Authorize]
        [HttpGet]
        public async Task<IActionResult> EditarPerfil()//la del formulario
        {
            var accessToken = await ObtenerTokenDeManagementAPI();
            var userId = User.FindFirst("sub")?.Value; //esta linea siempre sale null lo que no deja que funcione el metodo

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var response = await client.GetAsync($"https://dev-imu8ivfjqyn8g7x.us.auth0.com/api/v2/users/{userId}");//lo del dev es mi dominio de auth0

                if (!response.IsSuccessStatusCode)
                    return View(new UserProfileEditViewModel());

                var json = await response.Content.ReadAsStringAsync();

                var doc = JsonDocument.Parse(json);

                if (!doc.RootElement.TryGetProperty("user_metadata", out JsonElement metadataElement))
                    return View(new UserProfileEditViewModel()); // No hay metadata aún

                var metadata = metadataElement.Deserialize<UserProfileEditViewModel>();

                return View(metadata);
            }
        }


        [Authorize]
        [HttpPost]
        public async Task<IActionResult> EditarPerfil(UserProfileEditViewModel model)
        {
            var accessToken = await ObtenerTokenDeManagementAPI();
            var userId = User.FindFirst("sub")?.Value; //esta linea siempre sale null lo que no deja que funcione el metodo

            var update = new
            {
                user_metadata = new
                {
                    model.Tipodocumento,
                    model.Numerodocumento,
                    model.Direccion,
                    model.Telefono
                }
            };

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var content = new StringContent(JsonSerializer.Serialize(update), Encoding.UTF8, "application/json");

                var request = new HttpRequestMessage(HttpMethod.Patch, $"https://dev-imu8ivfjqyn8g7x.us.auth0.com/api/v2/users/{userId}")
                {
                    Content = content
                };

                var response = await client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    TempData["Success"] = "Datos actualizados correctamente.";
                    return RedirectToAction("Profile");
                }

                ModelState.AddModelError("", "Error al actualizar los datos.");
                return View(model);
            }
        }

        private async Task<string> ObtenerTokenDeManagementAPI()//sacar el token 
        {
            var client = new HttpClient();

            var body = new
            {
                client_id = "VWxUoVYbuDkBRT811CTQuNOQjiyIxYMS", // client_id de "TallerAplicaciones"
                client_secret = "JG53zYHbuplpq8OqDYIhZXMkeuAQ2I12e5lqhA-s9fzzOWjc3Y9PJLeeNuRtrj5o",
                audience = "https://dev-imu8ivfjqybn8g7x.us.auth0.com/api/v2/",
                grant_type = "client_credentials"
            };

            var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            var response = await client.PostAsync("https://dev-imu8ivfjqybn8g7x.us.auth0.com/oauth/token", content);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var doc = JsonDocument.Parse(json);
            return doc.RootElement.GetProperty("access_token").GetString();
        }


    }
}
