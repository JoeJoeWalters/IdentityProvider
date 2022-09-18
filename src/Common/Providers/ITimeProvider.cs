using System;
using System.Collections.Generic;
using System.Text;

namespace IdentityProvider.Common.Providers;

/// <summary>
/// Time provider to provide a way to inject a given time and fast forward if testing
/// </summary>
public interface ITimeProvider
{
    /// <summary>
    /// Get the current time
    /// </summary>
    /// <returns>The current Time</returns>
    DateTime Now();

    /// <summary>
    /// Set the current time, if used for testing otherwise will throw and exception
    /// </summary>
    /// <param name="cuurentTime">The new current time</param>
    void Set(DateTime cuurentTime);
}
