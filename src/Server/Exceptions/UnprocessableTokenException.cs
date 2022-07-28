﻿namespace Server.Exceptions
{
    /// <summary>
    /// 
    /// </summary>
    public class UnprocessableTokenException : Exception
    {
        /// <summary>
        /// 
        /// </summary>
        public UnprocessableTokenException() : base("Unprocessable Token, Check Token is of correct type")
        {

        }
    }
}
