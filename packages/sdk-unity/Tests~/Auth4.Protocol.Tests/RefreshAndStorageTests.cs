using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using static Auth4.Protocol.Tests.Fixtures;

namespace Auth4.Protocol.Tests
{
    public sealed class RefreshAndStorageTests
    {
        /// <summary>Guest creation plus a refresh endpoint that rotates on every call.</summary>
        private sealed class RotatingServer
        {
            public int Refreshes;
            public TaskCompletionSource<bool> Gate;
            public string RejectWith;

            public FakeTransport Transport()
            {
                return new FakeTransport(async request =>
                {
                    if (request.Path.EndsWith("/guest"))
                    {
                        return FakeTransport.Json(200, GuestCreated("access-0", "refresh-0"));
                    }

                    if (request.Path == "/oauth/revoke")
                    {
                        return FakeTransport.Json(200, string.Empty);
                    }

                    if (Gate != null)
                    {
                        await Gate.Task;
                    }

                    if (RejectWith != null)
                    {
                        return FakeTransport.Json(400, Error(RejectWith));
                    }

                    var generation = Interlocked.Increment(ref Refreshes);
                    return FakeTransport.Json(200, TokenJson("access-" + generation, "refresh-" + generation));
                });
            }
        }

        [Test]
        public async Task ConcurrentCallersShareOneRefreshAndRotationIsFollowed()
        {
            var server = new RotatingServer { Gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously) };
            var transport = server.Transport();
            var clock = new FakeClock();
            var client = Client(transport, clock);
            await client.SignInAsGuestAsync();
            clock.Advance(TimeSpan.FromMinutes(5));

            var callers = Enumerable.Range(0, 8).Select(_ => client.GetAccessTokenAsync()).ToList();
            Assert.That(callers.Any(caller => caller.IsCompleted), Is.False);
            server.Gate.SetResult(true);
            var tokens = await Task.WhenAll(callers);

            Assert.That(server.Refreshes, Is.EqualTo(1));
            Assert.That(tokens.Distinct().Single(), Is.EqualTo(Token("access-1")));
            var first = transport.To("/oauth/token").Single();
            Assert.That(first.Form["grant_type"], Is.EqualTo("refresh_token"));
            Assert.That(first.Form["refresh_token"], Is.EqualTo(Token("refresh-0")));
            Assert.That(first.Form["client_id"], Is.EqualTo(ClientId));
            Assert.That(first.Form.ContainsKey("client_secret"), Is.False);
            Assert.That(client.CurrentSession.UserId, Is.EqualTo(GuestUserId));
            Assert.That(client.CurrentSession.IsGuest, Is.True);

            clock.Advance(TimeSpan.FromMinutes(5));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("access-2")));
            var presented = transport.To("/oauth/token").Select(request => request.Form["refresh_token"]).ToList();
            Assert.That(presented, Is.EqualTo(new[] { Token("refresh-0"), Token("refresh-1") }));
        }

        [Test]
        public async Task ValidAccessTokenIsReusedUntilRefreshMargin()
        {
            var server = new RotatingServer();
            var clock = new FakeClock();
            var client = Client(server.Transport(), clock);
            await client.SignInAsGuestAsync();

            clock.Advance(TimeSpan.FromSeconds(269));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("access-0")));
            clock.Advance(TimeSpan.FromSeconds(2));
            Assert.That(await client.GetAccessTokenAsync(), Is.EqualTo(Token("access-1")));
        }

        [Test]
        public async Task CancelledWaiterDoesNotAbortSharedRefresh()
        {
            var server = new RotatingServer { Gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously) };
            var storage = new FakeSecureStorage();
            var client = Client(server.Transport(), new FakeClock(), storage);
            await client.SignInAsGuestAsync();

            using (var cancellation = new CancellationTokenSource())
            {
                var cancelled = client.RefreshAsync(cancellation.Token);
                var waiting = client.RefreshAsync();
                cancellation.Cancel();
                Assert.CatchAsync<OperationCanceledException>(() => cancelled);
                server.Gate.SetResult(true);
                await waiting;
            }

            Assert.That(server.Refreshes, Is.EqualTo(1));
            Assert.That(storage.Values.Values.Single(), Does.Contain(Token("refresh-1")));
        }

        [Test]
        public async Task RejectedRefreshEndsSessionAndClearsStorage()
        {
            var server = new RotatingServer();
            var storage = new FakeSecureStorage();
            var client = Client(server.Transport(), new FakeClock(), storage);
            await client.SignInAsGuestAsync();
            var changes = 0;
            Auth4Session last = client.CurrentSession;
            client.SessionChanged += session =>
            {
                changes++;
                last = session;
            };
            server.RejectWith = "invalid_grant";

            Assert.ThrowsAsync<Auth4SessionExpiredException>(() => client.RefreshAsync());

            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(storage.Values, Is.Empty);
            Assert.That(changes, Is.EqualTo(1));
            Assert.That(last, Is.Null);
            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.GetAccessTokenAsync());
            Assert.That(error.Error, Is.EqualTo("login_required"));
        }

        [Test]
        public async Task TransientRefreshFailureKeepsSession()
        {
            var server = new RotatingServer();
            var client = Client(server.Transport(), new FakeClock());
            await client.SignInAsGuestAsync();
            server.RejectWith = "temporarily_unavailable";

            var error = Assert.ThrowsAsync<Auth4Exception>(() => client.RefreshAsync());

            Assert.That(error.IsTransient, Is.True);
            Assert.That(client.CurrentSession, Is.Not.Null);
        }

        [Test]
        public async Task SignOutRevokesRefreshTokenAndClearsState()
        {
            var server = new RotatingServer();
            var transport = server.Transport();
            var storage = new FakeSecureStorage();
            var client = Client(transport, new FakeClock(), storage);
            await client.SignInAsGuestAsync();

            Assert.That(await client.SignOutAsync(), Is.True);

            var revoke = transport.To("/oauth/revoke").Single();
            Assert.That(revoke.Uri.Query, Is.EqualTo("?tenant_id=" + TenantId));
            Assert.That(revoke.Form["token"], Is.EqualTo(Token("refresh-0")));
            Assert.That(revoke.Form["token_type_hint"], Is.EqualTo("refresh_token"));
            Assert.That(revoke.Form["client_id"], Is.EqualTo(ClientId));
            Assert.That(client.CurrentSession, Is.Null);
            Assert.That(storage.Values, Is.Empty);
        }

        [Test]
        public async Task SignOutClearsLocallyWhenRevocationFails()
        {
            var online = true;
            var client = Client(
                new FakeTransport(request =>
                {
                    if (!online)
                    {
                        throw new IOException("offline");
                    }

                    return FakeTransport.Json(200, GuestCreated());
                }),
                new FakeClock());
            await client.SignInAsGuestAsync();
            online = false;

            Assert.That(await client.SignOutAsync(), Is.False);
            Assert.That(client.CurrentSession, Is.Null);
        }

        [Test]
        public async Task WithoutSecureAdapterNothingPersists()
        {
            var server = new RotatingServer();
            var transport = server.Transport();
            var first = Client(transport, new FakeClock());
            await first.SignInAsGuestAsync();

            Assert.That(first.IsRefreshPersistent, Is.False);
            Assert.That(first.CurrentSession.IsRefreshPersistent, Is.False);
            var restarted = Client(transport, new FakeClock());
            Assert.That(await restarted.TryRestoreSessionAsync(), Is.False);
            Assert.That(transport.To("/oauth/token"), Is.Empty);
        }

        [Test]
        public async Task SecureAdapterRestoresGuestAcrossRestart()
        {
            var server = new RotatingServer();
            var transport = server.Transport();
            var storage = new FakeSecureStorage();
            var first = Client(transport, new FakeClock(), storage);
            await first.SignInAsGuestAsync();

            Assert.That(first.IsRefreshPersistent, Is.True);
            Assert.That(storage.Values.Keys.Single(), Is.EqualTo("auth4." + TenantId + "." + ClientId + ".session"));
            Assert.That(storage.Values.Values.Single(), Does.Not.Contain(Token("access-0")));

            var restarted = Client(transport, new FakeClock(), storage);
            Assert.That(await restarted.TryRestoreSessionAsync(), Is.True);
            Assert.That(restarted.CurrentSession.UserId, Is.EqualTo(GuestUserId));
            Assert.That(restarted.CurrentSession.IsGuest, Is.True);
            Assert.That(transport.To("/oauth/token").Single().Form["refresh_token"], Is.EqualTo(Token("refresh-0")));
            Assert.That(storage.Values.Values.Single(), Does.Contain(Token("refresh-1")));
        }

        [Test]
        public async Task RestoreWithRevokedTokenReturnsFalse()
        {
            var server = new RotatingServer();
            var storage = new FakeSecureStorage();
            await Client(server.Transport(), new FakeClock(), storage).SignInAsGuestAsync();
            server.RejectWith = "invalid_grant";

            var restarted = Client(server.Transport(), new FakeClock(), storage);
            Assert.That(await restarted.TryRestoreSessionAsync(), Is.False);
            Assert.That(storage.Values, Is.Empty);
        }

        [Test]
        public void OptionsRejectInsecureOriginsAndBadIds()
        {
            Assert.Throws<ArgumentException>(() => new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId, ClientId = ClientId, AuthOrigin = "http://auth.example.test",
            }));
            Assert.Throws<ArgumentException>(() => new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId, ClientId = ClientId, AuthOrigin = Origin + "/t/" + TenantId,
            }));
            Assert.Throws<ArgumentException>(() => new Auth4Client(new Auth4ClientOptions
            {
                TenantId = "tenant", ClientId = ClientId, AuthOrigin = Origin,
            }));
            Assert.DoesNotThrow(() => new Auth4Client(new Auth4ClientOptions
            {
                TenantId = TenantId, ClientId = ClientId, AuthOrigin = "http://127.0.0.1:8787",
            }).Dispose());
        }

        [Test]
        public void PackageSourcesNeverUsePlayerPrefs()
        {
            var packageRoot = FindPackageRoot();
            var offenders = new[] { "Runtime", "Samples~" }
                .SelectMany(folder => Directory.GetFiles(Path.Combine(packageRoot, folder), "*.cs", SearchOption.AllDirectories))
                .Where(file => System.Text.RegularExpressions.Regex.IsMatch(File.ReadAllText(file), @"\bPlayerPrefs\s*\."))
                .ToList();
            Assert.That(offenders, Is.Empty);
        }

        private static string FindPackageRoot()
        {
            var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
            while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Runtime", "Auth4.Runtime.asmdef")))
            {
                directory = directory.Parent;
            }

            Assert.That(directory, Is.Not.Null, "Could not locate the Unity package root.");
            return directory.FullName;
        }
    }
}
