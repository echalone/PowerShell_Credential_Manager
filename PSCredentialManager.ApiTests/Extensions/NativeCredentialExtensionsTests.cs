using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSCredentialManager.Api.Extensions;
using PSCredentialManager.Common;
using PSCredentialManager.Common.Enum;
using System.Linq;

namespace PSCredentialManager.ApiTests.Extensions
{
    [TestClass()]
    public class NativeCredentialExtensionsTests
    {
        [TestMethod()]
        public void ToCredentialTest()
        {
            NativeCredential nativeCredential = new NativeCredential()
            {
                AttributeCount = 0,
                Attributes = new IntPtr(0),
                Comment = new IntPtr(0),
                CredentialBlob = new IntPtr(0),
                CredentialBlobSize = 0,
                Flags = 0,
                LastWritten = new System.Runtime.InteropServices.ComTypes.FILETIME(),
                Persist = 0,
                TargetAlias = new IntPtr(0),
                TargetName = new IntPtr(0),
                Type = CredType.Generic,
                UserName = new IntPtr(0)
            };

            Credential credential = nativeCredential.ToCredential(true, true);

            Assert.IsNotNull(credential);
            Assert.IsInstanceOfType(credential, typeof(Credential));
        }

        [TestMethod()]
        public void ToCredentialTestFilledValues()
        {
            Credential credential = new Credential()
            {
                AttributeCount = 0,
                Attributes = new IntPtr(0),
                Comment = "This is a comment",
                Password = "April123!!",
                PaswordSize = 20,
                Flags = 0,
                LastWritten = DateTime.Now,
                Persist = CredPersist.LocalMachine,
                TargetName = "server01",
                Type = CredType.Generic,
                UserName = "test-user"
            };

            NativeCredential nativeCredential = credential.ToNativeCredential();

            Assert.IsNotNull(nativeCredential);
            Assert.IsInstanceOfType(nativeCredential, typeof(NativeCredential));
            string ncUserName = System.Runtime.InteropServices.Marshal.PtrToStringUni(nativeCredential.UserName);
            Assert.IsNotNull(ncUserName);
            Assert.AreEqual(credential.UserName, ncUserName);

            Credential convertedOnlyClear = nativeCredential.ToCredential(true, false);
            Assert.IsNotNull(convertedOnlyClear);
            Assert.IsInstanceOfType(convertedOnlyClear, typeof(Credential));
            Assert.IsNotNull(convertedOnlyClear.UserName);
            Assert.AreEqual(credential.UserName, convertedOnlyClear.UserName);
            Assert.IsNotNull(convertedOnlyClear.Password);
            Assert.AreEqual(credential.Password, convertedOnlyClear.Password);
            Assert.AreEqual(credential.PaswordSize, convertedOnlyClear.PaswordSize);
            Assert.IsNull(convertedOnlyClear.SecurePassword);

            Credential convertedOnlySecure = nativeCredential.ToCredential(false, true);
            Assert.IsNotNull(convertedOnlySecure);
            Assert.IsInstanceOfType(convertedOnlySecure, typeof(Credential));
            Assert.IsNotNull(convertedOnlySecure.UserName);
            Assert.AreEqual(credential.UserName, convertedOnlySecure.UserName);
            Assert.IsNotNull(convertedOnlySecure.SecurePassword);
            Assert.AreEqual(credential.Password, convertedOnlySecure.SecurePassword.ToInsecureString());
            Assert.AreEqual(uint.MinValue, convertedOnlySecure.PaswordSize);
            Assert.IsNull(convertedOnlySecure.Password);

            Credential convertedClearAndSecure = nativeCredential.ToCredential(true, true);
            Assert.IsNotNull(convertedClearAndSecure);
            Assert.IsInstanceOfType(convertedClearAndSecure, typeof(Credential));
            Assert.IsNotNull(convertedClearAndSecure.UserName);
            Assert.AreEqual(credential.UserName, convertedClearAndSecure.UserName);
            Assert.IsNotNull(convertedClearAndSecure.Password);
            Assert.IsNotNull(convertedClearAndSecure.SecurePassword);
            Assert.AreEqual(credential.Password, convertedClearAndSecure.Password);
            Assert.AreEqual(credential.PaswordSize, convertedClearAndSecure.PaswordSize);
            Assert.AreEqual(credential.Password, convertedClearAndSecure.SecurePassword.ToInsecureString());
            Assert.AreEqual(credential.PaswordSize, (uint)convertedClearAndSecure.SecurePassword.Length * 2);

        }

        [TestMethod()]
        public void ToCredentialTestFilledEmptyValues()
        {
            Credential credential = new Credential()
            {
                AttributeCount = 0,
                Attributes = new IntPtr(0),
                Comment = "",
                Password = "",
                PaswordSize = 0,
                Flags = 0,
                LastWritten = DateTime.Now,
                Persist = CredPersist.LocalMachine,
                TargetName = "",
                Type = CredType.Generic,
                UserName = ""
            };

            NativeCredential nativeCredential = credential.ToNativeCredential();

            Assert.IsNotNull(nativeCredential);
            Assert.IsInstanceOfType(nativeCredential, typeof(NativeCredential));
            string ncUserName = System.Runtime.InteropServices.Marshal.PtrToStringUni(nativeCredential.UserName);
            Assert.IsNotNull(ncUserName);
            Assert.AreEqual(credential.UserName, ncUserName);

            Credential convertedOnlyClear = nativeCredential.ToCredential(true, false);
            Assert.IsNotNull(convertedOnlyClear);
            Assert.IsInstanceOfType(convertedOnlyClear, typeof(Credential));
            Assert.IsNotNull(convertedOnlyClear.UserName);
            Assert.AreEqual(credential.UserName, convertedOnlyClear.UserName);
            Assert.IsNotNull(convertedOnlyClear.Password);
            Assert.AreEqual(credential.Password, convertedOnlyClear.Password);
            Assert.AreEqual(credential.PaswordSize, convertedOnlyClear.PaswordSize);
            Assert.IsNull(convertedOnlyClear.SecurePassword);

            Credential convertedOnlySecure = nativeCredential.ToCredential(false, true);
            Assert.IsNotNull(convertedOnlySecure);
            Assert.IsInstanceOfType(convertedOnlySecure, typeof(Credential));
            Assert.IsNotNull(convertedOnlySecure.UserName);
            Assert.AreEqual(credential.UserName, convertedOnlySecure.UserName);
            Assert.IsNotNull(convertedOnlySecure.SecurePassword);
            Assert.AreEqual(credential.Password, convertedOnlySecure.SecurePassword.ToInsecureString());
            Assert.AreEqual(uint.MinValue, convertedOnlySecure.PaswordSize);
            Assert.IsNull(convertedOnlySecure.Password);

            Credential convertedClearAndSecure = nativeCredential.ToCredential(true, true);
            Assert.IsNotNull(convertedClearAndSecure);
            Assert.IsInstanceOfType(convertedClearAndSecure, typeof(Credential));
            Assert.IsNotNull(convertedClearAndSecure.UserName);
            Assert.AreEqual(credential.UserName, convertedClearAndSecure.UserName);
            Assert.IsNotNull(convertedClearAndSecure.Password);
            Assert.IsNotNull(convertedClearAndSecure.SecurePassword);
            Assert.AreEqual(credential.Password, convertedClearAndSecure.Password);
            Assert.AreEqual(credential.PaswordSize, convertedClearAndSecure.PaswordSize);
            Assert.AreEqual(credential.Password, convertedClearAndSecure.SecurePassword.ToInsecureString());
            Assert.AreEqual(credential.PaswordSize, (uint)convertedClearAndSecure.SecurePassword.Length * 2);

        }
    }
}