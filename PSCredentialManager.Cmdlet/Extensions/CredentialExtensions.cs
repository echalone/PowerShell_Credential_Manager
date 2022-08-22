using PSCredentialManager.Common;
using System;
using System.Management.Automation;

namespace PSCredentialManager.Cmdlet.Extensions
{
    public static class CredentialExtensions
    {
        public static PSCredential ToPsCredential(this Credential credential)
        {
            PSCredential psCredential;

            if (credential.UserName != null && (!string.IsNullOrEmpty(credential.Password) || credential.SecurePassword != null))
            {
                try
                {
                    psCredential = new PSCredential(credential.UserName, credential.SecurePassword ?? credential.Password.ToSecureString());
                }
                catch (Exception ex)
                {
                    throw new Exception("Unable to convert credential object", ex);
                }
            }
            else
            {
                throw new Exception("Unable to convert Credential object without username or password to PSCredential object");
            }

            return psCredential;
        }
    }
}
