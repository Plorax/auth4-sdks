using System;
using System.Threading;
using System.Threading.Tasks;

namespace Auth4
{
    /// <summary>Time source and delay used for token expiry and device polling.</summary>
    public interface IAuth4Clock
    {
        DateTimeOffset UtcNow { get; }

        Task Delay(TimeSpan delay, CancellationToken cancellationToken);
    }

    public sealed class SystemClock : IAuth4Clock
    {
        public static readonly SystemClock Instance = new SystemClock();

        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

        public Task Delay(TimeSpan delay, CancellationToken cancellationToken)
        {
            return delay <= TimeSpan.Zero ? Task.CompletedTask : Task.Delay(delay, cancellationToken);
        }
    }
}
