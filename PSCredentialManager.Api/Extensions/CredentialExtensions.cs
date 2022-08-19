﻿using PSCredentialManager.Common;
using System;
using System.Runtime.InteropServices;

namespace PSCredentialManager.Api.Extensions
{
    public static class CredentialExtensions
    {      
        public static NativeCredential ToNativeCredential(this Credential credential)
        {
            NativeCredential nativeCredential;

            try
            {
                nativeCredential = new NativeCredential()
                {
                    AttributeCount = 0,
                    Attributes = IntPtr.Zero,
                    Comment = Marshal.StringToCoTaskMemUni(credential.Comment),
                    TargetAlias = IntPtr.Zero,
                    Type = credential.Type,
                    Persist = (uint)credential.Persist,
                    CredentialBlobSize = credential.SecurePassword != null ? (uint)credential.SecurePassword.Length * 2 : credential.PaswordSize,
                    TargetName = Marshal.StringToCoTaskMemUni(credential.TargetName),
                    CredentialBlob = credential.SecurePassword != null ? Marshal.SecureStringToCoTaskMemUnicode(credential.SecurePassword) : Marshal.StringToCoTaskMemUni(credential.Password),
                    UserName = Marshal.StringToCoTaskMemUni(credential.UserName),
                    LastWritten = credential.LastWritten.ToComFileTime()
                };
            }
            catch (Exception ex)
            {
                throw new Exception("PSCredentialManager.Api.CredentialUtility.ConvertToNativeCredential Unable to convert credential to native credential.", ex);
            }

            return nativeCredential;
        }
    }
}
