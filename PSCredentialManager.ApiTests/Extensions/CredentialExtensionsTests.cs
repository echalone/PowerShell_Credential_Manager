using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSCredentialManager.Api.Extensions;
using PSCredentialManager.Common;
using PSCredentialManager.Common.Enum;

namespace PSCredentialManager.ApiTests.Extensions
{
    [TestClass()]
    public class CredentialExtensionsTests
    {
        [TestMethod()]
        public void ToNativeCredentialTest()
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
            Assert.AreEqual(credential.Password, convertedOnlyClear.Password);
        }

    }
}