using System;
using System.Collections.Generic;
using System.Text;

namespace IdentityProvider.Common.Providers;

/// <summary>
/// Real time provider 
/// </summary>
public class TimeProvider : ITimeProvider
{
    /// <summary>
    /// Get the current time
    /// </summary>
    /// <returns>The current time in UTC</returns>
    public DateTime Now() => DateTime.UtcNow;

    /// <summary>
    /// Cannot set the current time with this provider 
    /// </summary>
    /// <param name="cuurentTime">The current time</param>
    /// <exception cref="NotImplementedException">Cannot set the current time</exception>
    public void Set(DateTime cuurentTime) => throw new NotImplementedException();
}
