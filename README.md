This project allows the decryption of cookies set via Forms Authentication
(assuming the necessary keys are known). It does **NOT** require referencing
System.Web or running in the context of ASP.NET.  

This code uses code modified from the .NET Framework 4.6 licensed under the MIT
license (https://github.com/Microsoft/referencesource). The code was modified
to be able to work with cookies outside the context of a web application.

The license for this code is also MIT License (see License file). Feel free
to do whatever you'd like.

Usage
=====

```C#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Security;

namespace MyCode
{
    public class CookieDecryptor
    {
        private readonly string decryptionKey;
        private readonly string validationKey;
        private readonly string validationType;

        public CookieDecryptor(string decryptionKey, string validationType, string validationKey)
        {
            if (string.IsNullOrWhiteSpace(decryptionKey)) throw new ArgumentNullException("decryptionKey");
            if (string.IsNullOrWhiteSpace(validationType)) throw new ArgumentNullException("validationType");
            if (string.IsNullOrWhiteSpace(validationKey)) throw new ArgumentNullException("validationKey"); 
            this.validationType = validationType;
            this.decryptionKey = decryptionKey;
            this.validationKey = validationKey;
        }

        public FormsAuthenticationTicket DecryptCookieValue(string cookie)
        {
            var ticket = FormsAuthOnly.Security.FormsAuthentication.Decrypt(cookie, decryptionKey, validationType, validationKey);
            return new FormsAuthenticationTicket(ticket.Version, ticket.Name, ticket.IssueDate, ticket.Expiration, ticket.IsPersistent, ticket.UserData, ticket.CookiePath);
        }
    }
}
```