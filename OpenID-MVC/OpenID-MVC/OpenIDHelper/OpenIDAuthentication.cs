using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Security.Claims;

namespace OpenID_MVC.OpenIDHelper
{
    public class OpenIDAuthentication
    {
        private static OpenIDInfoRecord? info = null;
        private static string? theProvider = null;
        //private static string? theMeta = null;
        private static string? theRealm = null;
        private static string? theClient = null;
        private static string? theSecret = null;
        /// <summary>
        /// Loads all info pertaining to an OpenID Identity Provider
        /// </summary>
        /// <param name="ServerURL">
        /// ex: auth.c.ucnit.eu
        /// </param>
        /// <param name="Realm">
        /// ex: xOIDCx
        /// </param>
        public OpenIDAuthentication()
        {
            // There can be only one
            if (info != null) return;
            theProvider = Environment.GetEnvironmentVariable("OpenIDProvider");
            theRealm = Environment.GetEnvironmentVariable("OpenIDRealm");
            theClient = Environment.GetEnvironmentVariable("OpenIDClient");
            theSecret = Environment.GetEnvironmentVariable("OpenIDSecret");
            //theMeta = "https://" + theProvider + "/realms/" + theRealm + "/.well-known/openid-configuration";
            // The resulting URL for a newer KeyCloak will be https://+ServerURL+/realms/+Realm+/.well-known/openid-configuration
            var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Get, "https://" + theProvider + "/realms/" + theRealm + "/.well-known/openid-configuration");
            var response = client.SendAsync(request).Result;
            response.EnsureSuccessStatusCode();
            String jsonStr = response.Content.ReadAsStringAsync().Result;
            info = JsonConvert.DeserializeObject<OpenIDInfoRecord>(jsonStr);
        }

        public void AddServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                //Sets cookie authentication scheme
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })

            .AddCookie(cookie =>
            {
                //Sets the cookie name and maxage, so the cookie is invalidated.
                cookie.Cookie.Name = "keycloak.cookie";
                cookie.Cookie.MaxAge = TimeSpan.FromMinutes(60);
                cookie.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                cookie.SlidingExpiration = true;
            })
            .AddOpenIdConnect(options =>
            {
                /*
                 * ASP.NET core uses the http://*:5000 and https://*:5001 ports for default communication with the OIDC middleware
                 * The app requires load balancing services to work with :80 or :443
                 * These needs to be added to the keycloak client, in order for the redirect to work.
                 * If you however intend to use the app by itself then,
                 * Change the ports in launchsettings.json, but beware to also change the options.CallbackPath and options.SignedOutCallbackPath!
                 * Use LB services whenever possible, to reduce the config hazzle :)
                */

                //Use default signin scheme
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                //Keycloak server  ::  Authority	OpenIDRealmURI: https://auth.c.ucnit.eu/realms/xOIDCx
                options.Authority = info.issuer;
                //Keycloak client ID  ::            OpenIDClient: Alice
                options.ClientId = theClient;
                //Keycloak client secret  ::        OpenIDSecret: 6zaZi58YBm24WgURUBtn5fbKVFGz8jsy
                options.ClientSecret = theSecret;
                //Keycloak .wellknown config origin to fetch config
                options.MetadataAddress = "https://" + theProvider + "/realms/" + theRealm + "/.well-known/openid-configuration";
                //Require keycloak to use SSL
                options.RequireHttpsMetadata = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.Scope.Add("roles");
                //Save the token
                options.SaveTokens = true;
                //Token response type, will sometimes need to be changed to IdToken, depending on config.
                options.ResponseType = OpenIdConnectResponseType.Code;
                //SameSite is needed for Chrome/Firefox, as they will give http error 500 back, if not set to unspecified.
                options.NonceCookie.SameSite = SameSiteMode.Unspecified;
                options.CorrelationCookie.SameSite = SameSiteMode.Unspecified;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = ClaimTypes.Role,
                    ValidateIssuer = true
                };
            });

            /*
             * For roles, that are defined in the keycloak, you need to use ClaimTypes.Role
             * You also need to configure keycloak, to set the correct name on each token.
             * Keycloak Admin Console -> Client Scopes -> roles -> mappers -> create
             * Name: "role client mapper" or whatever you prefer
             * Mapper Type: "User Client Role"
             * Multivalued: True
             * Token Claim Name: role
             * Add to access token: True
             */


            /*
             * Policy based authentication
             */

            services.AddAuthorization(options =>
            {
                //Create policy with more than one claim
                options.AddPolicy("users", policy =>
                policy.RequireAssertion(context =>
                context.User.HasClaim(c =>
                        (c.Value == "user") || (c.Value == "Admin"))));
                //Create policy with only one claim
                options.AddPolicy("admins", policy =>
                    policy.RequireClaim(ClaimTypes.Role, "Admin"));
                //Create a policy with a claim that doesn't exist or you are unauthorized to
                options.AddPolicy("noaccess", policy =>
                    policy.RequireClaim(ClaimTypes.Role, "noaccess"));
            });
        }
    }

    // Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse);
    internal class MtlsEndpointAliases
    {
        public string token_endpoint { get; set; }
        public string revocation_endpoint { get; set; }
        public string introspection_endpoint { get; set; }
        public string device_authorization_endpoint { get; set; }
        public string registration_endpoint { get; set; }
        public string userinfo_endpoint { get; set; }
        public string pushed_authorization_request_endpoint { get; set; }
        public string backchannel_authentication_endpoint { get; set; }
    }

    internal class OpenIDInfoRecord
    {
        public string issuer { get; set; }
        public string authorization_endpoint { get; set; }
        public string token_endpoint { get; set; }
        public string introspection_endpoint { get; set; }
        public string userinfo_endpoint { get; set; }
        public string end_session_endpoint { get; set; }
        public bool frontchannel_logout_session_supported { get; set; }
        public bool frontchannel_logout_supported { get; set; }
        public string jwks_uri { get; set; }
        public string check_session_iframe { get; set; }
        public List<string> grant_types_supported { get; set; }
        public List<string> acr_values_supported { get; set; }
        public List<string> response_types_supported { get; set; }
        public List<string> subject_types_supported { get; set; }
        public List<string> id_token_signing_alg_values_supported { get; set; }
        public List<string> id_token_encryption_alg_values_supported { get; set; }
        public List<string> id_token_encryption_enc_values_supported { get; set; }
        public List<string> userinfo_signing_alg_values_supported { get; set; }
        public List<string> userinfo_encryption_alg_values_supported { get; set; }
        public List<string> userinfo_encryption_enc_values_supported { get; set; }
        public List<string> request_object_signing_alg_values_supported { get; set; }
        public List<string> request_object_encryption_alg_values_supported { get; set; }
        public List<string> request_object_encryption_enc_values_supported { get; set; }
        public List<string> response_modes_supported { get; set; }
        public string registration_endpoint { get; set; }
        public List<string> token_endpoint_auth_methods_supported { get; set; }
        public List<string> token_endpoint_auth_signing_alg_values_supported { get; set; }
        public List<string> introspection_endpoint_auth_methods_supported { get; set; }
        public List<string> introspection_endpoint_auth_signing_alg_values_supported { get; set; }
        public List<string> authorization_signing_alg_values_supported { get; set; }
        public List<string> authorization_encryption_alg_values_supported { get; set; }
        public List<string> authorization_encryption_enc_values_supported { get; set; }
        public List<string> claims_supported { get; set; }
        public List<string> claim_types_supported { get; set; }
        public bool claims_parameter_supported { get; set; }
        public List<string> scopes_supported { get; set; }
        public bool request_parameter_supported { get; set; }
        public bool request_uri_parameter_supported { get; set; }
        public bool require_request_uri_registration { get; set; }
        public List<string> code_challenge_methods_supported { get; set; }
        public bool tls_client_certificate_bound_access_tokens { get; set; }
        public string revocation_endpoint { get; set; }
        public List<string> revocation_endpoint_auth_methods_supported { get; set; }
        public List<string> revocation_endpoint_auth_signing_alg_values_supported { get; set; }
        public bool backchannel_logout_supported { get; set; }
        public bool backchannel_logout_session_supported { get; set; }
        public string device_authorization_endpoint { get; set; }
        public List<string> backchannel_token_delivery_modes_supported { get; set; }
        public string backchannel_authentication_endpoint { get; set; }
        public List<string> backchannel_authentication_request_signing_alg_values_supported { get; set; }
        public bool require_pushed_authorization_requests { get; set; }
        public string pushed_authorization_request_endpoint { get; set; }
        public MtlsEndpointAliases mtls_endpoint_aliases { get; set; }
        public bool authorization_response_iss_parameter_supported { get; set; }
    }


}
