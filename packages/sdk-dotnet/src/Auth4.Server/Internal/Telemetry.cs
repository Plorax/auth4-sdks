using System;
using System.Threading.Tasks;
#if NET8_0_OR_GREATER
using System.Diagnostics;
using System.Diagnostics.Metrics;
#endif

namespace Auth4.Server.Internal
{
    /// <summary>
    /// AUTH4D-391: records one operation's duration and outcome. On net8.0 it feeds the public
    /// <c>Auth4.Server</c> ActivitySource and Meter; on netstandard2.1 every call is a no-op. It
    /// only ever receives an operation name and an outcome, so no token, claim or message can reach it.
    /// </summary>
    internal static class Telemetry
    {
        public const string ValidateAccessToken = "validate_access_token";
        public const string ValidateIdToken = "validate_id_token";
        public const string JwksFetch = "jwks_fetch";
        public const string Introspect = "introspect";

        public const string Success = "success";
        public const string InvalidToken = "invalid_token";
        public const string Unavailable = "unavailable";
        public const string RefreshLimited = "refresh_limited";
        public const string Error = "error";

#if NET8_0_OR_GREATER
        private static readonly string Version = typeof(Telemetry).Assembly.GetName().Version?.ToString() ?? "0.0.0";
        private static readonly ActivitySource Source = new ActivitySource(Auth4Diagnostics.ActivitySourceName, Version);
        private static readonly Meter Instruments = new Meter(Auth4Diagnostics.MeterName, Version);
        private static readonly Histogram<double> Duration =
            Instruments.CreateHistogram<double>("auth4.server.operation.duration", "s", "Duration of Auth4.Server verification and dependency operations.");
        private static readonly Counter<long> Count =
            Instruments.CreateCounter<long>("auth4.server.operation.count", "{operation}", "Auth4.Server operations by outcome.");
#endif

        public static Scope Begin(string operation)
        {
#if NET8_0_OR_GREATER
            var local = operation == ValidateAccessToken || operation == ValidateIdToken;
            var activity = Source.StartActivity("auth4." + operation, local ? ActivityKind.Internal : ActivityKind.Client);
            activity?.SetTag("auth4.operation", operation);
            return new Scope(operation, activity, Stopwatch.GetTimestamp());
#else
            return default;
#endif
        }

        /// <summary>Records an operation that took no time, such as a refused key refresh.</summary>
        public static void Instant(string operation, string outcome) => Begin(operation).End(outcome);

        /// <summary>Runs <paramref name="body"/> and records its outcome; any exception passes through unchanged.</summary>
        public static async Task<T> TrackAsync<T>(string operation, Func<Task<T>> body)
        {
            var scope = Begin(operation);
            try
            {
                var result = await body().ConfigureAwait(false);
                scope.End(Success);
                return result;
            }
            catch (Exception cause)
            {
                scope.End(Classify(cause));
                throw;
            }
        }

        /// <summary>Maps a failure to a bounded outcome using only the typed error code.</summary>
        public static string Classify(Exception cause)
        {
            if (cause is Auth4TokenException token)
            {
                switch (token.Code)
                {
                    case Auth4TokenErrorCode.InvalidToken: return InvalidToken;
                    case Auth4TokenErrorCode.JwksRefreshLimited: return RefreshLimited;
                    default: return Unavailable;
                }
            }
            return Error;
        }

        internal readonly struct Scope
        {
#if NET8_0_OR_GREATER
            private readonly string operation;
            private readonly Activity? activity;
            private readonly long started;

            public Scope(string operation, Activity? activity, long started)
            {
                this.operation = operation;
                this.activity = activity;
                this.started = started;
            }

            public void End(string outcome)
            {
                var seconds = Stopwatch.GetElapsedTime(started).TotalSeconds;
                var tags = new TagList { { "auth4.operation", operation }, { "auth4.outcome", outcome } };
                Duration.Record(seconds, tags);
                Count.Add(1, tags);
                if (activity != null)
                {
                    activity.SetTag("auth4.outcome", outcome);
                    if (outcome != Success && outcome != InvalidToken) activity.SetStatus(ActivityStatusCode.Error);
                    activity.Dispose();
                }
            }
#else
            public void End(string outcome)
            {
            }
#endif
        }
    }
}
