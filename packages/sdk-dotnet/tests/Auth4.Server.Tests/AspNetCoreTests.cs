using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Auth4.Server.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;

namespace Auth4.Server.Tests
{
    public class AspNetCoreTests
    {
        private TestKey key = null!;
        private FakeIssuer issuer = null!;
        private IHost host = null!;
        private HttpClient http = null!;

        [SetUp]
        public async Task SetUp()
        {
            key = new TestKey("key-1");
            issuer = new FakeIssuer(key);
            host = await new HostBuilder()
                .ConfigureWebHost(web => web
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        services.AddAuthentication(Auth4BearerDefaults.AuthenticationScheme)
                            .AddAuth4Bearer(options =>
                            {
                                options.TenantId = Ids.Tenant;
                                options.AuthOrigin = Ids.Origin;
                                options.Audience = Ids.Client;
                                options.HttpClient = issuer.Client();
                                options.Now = () => Ids.Now;
                            });
                        services.AddAuthorization(options =>
                        {
                            options.AddPolicy("players", policy => policy.RequireAuthenticatedUser().RequireNonGuest());
                            options.AddPolicy("email", policy => policy.RequireAuthenticatedUser().RequireScope("email"));
                        });
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseAuthentication();
                        app.UseAuthorization();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapGet("/public", () => "hello");
                            endpoints.MapGet("/me", (HttpContext context) => new
                            {
                                sub = context.User.Identity!.Name,
                                guest = context.User.IsAuth4Guest(),
                                roles = context.GetAuth4AccessToken()!.Roles,
                            }).RequireAuthorization();
                            endpoints.MapGet("/admin", () => "admin").RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { Roles = "admin" });
                            endpoints.MapGet("/players", () => "players").RequireAuthorization("players");
                            endpoints.MapGet("/email", () => "email").RequireAuthorization("email");
                        });
                    }))
                .StartAsync();
            http = host.GetTestClient();
        }

        [TearDown]
        public async Task TearDown()
        {
            http.Dispose();
            await host.StopAsync();
            host.Dispose();
            issuer.Dispose();
            key.Dispose();
        }

        private Task<HttpResponseMessage> Get(string path, string? token)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, path);
            if (token != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return http.SendAsync(request);
        }

        [Test]
        public async Task LetsAnonymousEndpointsThroughWithoutAHeader()
        {
            var response = await Get("/public", null);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(issuer.Requests, Is.Empty);
        }

        [Test]
        public async Task ChallengesMissingAndInvalidTokensWith401()
        {
            var missing = await Get("/me", null);
            Assert.That(missing.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(missing.Headers.WwwAuthenticate.ToString(), Is.EqualTo("Bearer realm=\"auth4\""));
            Assert.That(await missing.Content.ReadAsStringAsync(), Is.EqualTo("{\"error\":\"unauthorized\"}"));

            var invalid = await Get("/me", Tokens.Sign(key, Tokens.AccessClaims().With("aud", Ids.OtherClient)));
            Assert.That(invalid.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(invalid.Headers.WwwAuthenticate.ToString(), Does.Contain("error=\"invalid_token\""));
        }

        [Test]
        public async Task AuthenticatesAValidTokenAndExposesItsClaims()
        {
            var token = Tokens.Sign(key, Tokens.AccessClaims().With("auth4_roles", new[] { "admin" }).With("auth4_guest", true));
            var response = await Get("/me", token);
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(await response.Content.ReadAsStringAsync(), Is.EqualTo($"{{\"sub\":\"{Ids.User}\",\"guest\":true,\"roles\":[\"admin\"]}}"));
        }

        [Test]
        public async Task MapsRolesGuestsAndScopesToAuthorization()
        {
            var admin = Tokens.Sign(key, Tokens.AccessClaims().With("auth4_roles", new[] { "admin" }));
            var player = Tokens.Sign(key, Tokens.AccessClaims());
            var guest = Tokens.Sign(key, Tokens.AccessClaims().With("auth4_guest", true));
            Assert.That((await Get("/admin", admin)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await Get("/admin", player)).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That((await Get("/players", player)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await Get("/players", guest)).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That((await Get("/email", player)).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That((await Get("/email", Tokens.Sign(key, Tokens.AccessClaims().With("scope", "openid email")))).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }

        [Test]
        public async Task ReportsAKeyOutageAs503()
        {
            issuer.Route(Ids.Issuer + "/.well-known/jwks.json", _ => new HttpResponseMessage(HttpStatusCode.BadGateway));
            var response = await Get("/me", Tokens.Sign(key, Tokens.AccessClaims()));
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable));
            Assert.That(response.Headers.RetryAfter!.Delta, Is.EqualTo(TimeSpan.FromSeconds(5)));
        }

        [Test]
        public async Task SharesOneClientAndKeyCacheAcrossRequests()
        {
            var token = Tokens.Sign(key, Tokens.AccessClaims());
            await Get("/me", token);
            await Get("/me", token);
            Assert.That(issuer.Count(Ids.Issuer + "/.well-known/jwks.json"), Is.EqualTo(1));
            Assert.That(host.Services.GetRequiredService<Auth4BearerClients>().Get().Issuer, Is.EqualTo(Ids.Issuer));
        }
    }
}
