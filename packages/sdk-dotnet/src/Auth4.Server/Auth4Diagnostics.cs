#if NET8_0_OR_GREATER
namespace Auth4.Server
{
    /// <summary>
    /// Names of the System.Diagnostics sources the SDK emits on net8.0 (AUTH4D-391). Nothing is
    /// exported unless the host subscribes: add <see cref="ActivitySourceName"/> to a tracer
    /// provider and <see cref="MeterName"/> to a meter provider, or attach an ActivityListener or
    /// MeterListener. The netstandard2.1 build emits no diagnostics.
    /// <para>
    /// Activities (<c>auth4.validate_access_token</c>, <c>auth4.validate_id_token</c>,
    /// <c>auth4.jwks_fetch</c>, <c>auth4.introspect</c>) carry two tags, <c>auth4.operation</c> and
    /// <c>auth4.outcome</c>. The meter has the histogram <c>auth4.server.operation.duration</c>
    /// (seconds) and the counter <c>auth4.server.operation.count</c>, tagged the same way.
    /// </para>
    /// <para>
    /// <c>auth4.outcome</c> is one of <c>success</c>, <c>invalid_token</c> (the credential is bad),
    /// <c>unavailable</c> (the JWKS or introspection endpoint could not be used),
    /// <c>refresh_limited</c> (a key refresh was attempted too recently) or <c>error</c> (an
    /// unexpected exception). Activities for <c>unavailable</c>, <c>refresh_limited</c> and
    /// <c>error</c> get status Error. <c>jwks_fetch</c> counts network fetches only and
    /// <c>introspect</c> counts endpoint calls only; cache hits are not operations. Tokens,
    /// credentials, claims, subjects, request bodies and exception messages are never recorded.
    /// </para>
    /// </summary>
    public static class Auth4Diagnostics
    {
        /// <summary>The ActivitySource name, <c>Auth4.Server</c>.</summary>
        public const string ActivitySourceName = "Auth4.Server";

        /// <summary>The Meter name, <c>Auth4.Server</c>.</summary>
        public const string MeterName = "Auth4.Server";
    }
}
#endif
