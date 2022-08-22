﻿using System.Security;

namespace PSCredentialManager.ApiTests.Extensions
{
    public static class StringExtensions
    {
        public static SecureString ToSecureString(this string insecureString)
        {
            SecureString secureString = new SecureString();

            foreach (char character in insecureString)
            {
                secureString.AppendChar(character);
            }

            return secureString;
        }
    }
}
