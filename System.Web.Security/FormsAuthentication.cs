//------------------------------------------------------------------------------
// <copyright file="FormsAuthentication.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

/*
 * FormsAuthentication class
 *
 * Copyright (c) 1999 Microsoft Corporation
 */

namespace FormsAuthOnly.Security
{
    using System;
    using System.Web;
    using System.Text;
    using FormsAuthOnly.Configuration;
    using System.Collections;
    using FormsAuthOnly.Util;
    using System.Security.Cryptography;
    using System.Security.Principal;
    using System.Threading;
    using System.Globalization;
    using System.Security.Permissions;
    using System.Collections.Specialized;
    using FormsAuthOnly.Security.Cryptography;



    /// <devdoc>
    ///    This class consists of static methods that
    ///    provides helper utilities for manipulating authentication tickets.
    /// </devdoc>
    public sealed class FormsAuthentication
    {
        private const int MAX_TICKET_LENGTH = 4096;
        private static object _lockObject = new object();

        public FormsAuthentication() { }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        // Initialize this

        /// <devdoc>
        ///    Initializes FormsAuthentication by reading
        ///    configuration and getting the cookie values and encryption keys for the given
        ///    application.
        /// </devdoc>
        public static void Initialize()
        {
            if (_Initialized)
                return;

            lock (_lockObject) {
                if (_Initialized)
                    return;

                //AuthenticationSection settings = RuntimeConfig.GetAppConfig().Authentication;
                //settings.ValidateAuthenticationMode();
                //_FormsName = settings.Forms.Name;
                //_RequireSSL = settings.Forms.RequireSSL;
                //_SlidingExpiration = settings.Forms.SlidingExpiration;
                //if (_FormsName == null)
                //    _FormsName = CONFIG_DEFAULT_COOKIE;

                //_Protection = settings.Forms.Protection;
                //_Timeout = (int)settings.Forms.Timeout.TotalMinutes;
                //_FormsCookiePath = settings.Forms.Path;
                //_LoginUrl = settings.Forms.LoginUrl;
                //if (_LoginUrl == null)
                //    _LoginUrl = "login.aspx";
                //_DefaultUrl = settings.Forms.DefaultUrl;
                //if (_DefaultUrl == null)
                //    _DefaultUrl = "default.aspx";
                //_CookieMode = settings.Forms.Cookieless;
                //_CookieDomain = settings.Forms.Domain;
                //_EnableCrossAppRedirects = settings.Forms.EnableCrossAppRedirects;
                //_TicketCompatibilityMode = settings.Forms.TicketCompatibilityMode;

                _Initialized = true;
            }
        }


        public static FormsAuthenticationTicket Decrypt(string encryptedTicket, string decryptionKey, string validationType, string validationKey)
        {
            var section = MachineKeySection.GetApplicationConfig();
            section.DecryptionKey = decryptionKey;
            section.Validation = (MachineKeyValidation)Enum.Parse(typeof(MachineKeyValidation), validationType);
            section.ValidationKey = validationKey;
            section.CompatibilityMode = MachineKeyCompatibilityMode.Framework20SP2;
            return Decrypt(encryptedTicket);
        }
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        // Decrypt and get the auth ticket

        /// <devdoc>
        ///    <para>Given an encrypted authenitcation ticket as
        ///       obtained from an HTTP cookie, this method returns an instance of a
        ///       FormsAuthenticationTicket class.</para>
        /// </devdoc>
        public static FormsAuthenticationTicket Decrypt(string encryptedTicket)
        {
            if (String.IsNullOrEmpty(encryptedTicket) || encryptedTicket.Length > MAX_TICKET_LENGTH)
                throw new ArgumentException(SR.GetString(SR.InvalidArgumentValue, "encryptedTicket"));

            Initialize();
            byte[] bBlob = null;
            if ((encryptedTicket.Length % 2) == 0) { // Could be a hex string
                try {
                    bBlob = CryptoUtil.HexToBinary(encryptedTicket);
                }
                catch { }
            }
            if (bBlob == null)
                throw new NotImplementedException(); //bBlob = HttpServerUtility.UrlTokenDecode(encryptedTicket);
            if (bBlob == null || bBlob.Length < 1)
                throw new ArgumentException(SR.GetString(SR.InvalidArgumentValue, "encryptedTicket"));

            int ticketLength;

            if (AspNetCryptoServiceProvider.Instance.IsDefaultProvider) {
                // If new crypto routines are enabled, call them instead.
                ICryptoService cryptoService = AspNetCryptoServiceProvider.Instance.GetCryptoService(Purpose.FormsAuthentication_Ticket);
                byte[] unprotectedData = cryptoService.Unprotect(bBlob);
                ticketLength = unprotectedData.Length;
                bBlob = unprotectedData;
            } else {
#pragma warning disable 618 // calling obsolete methods
                // Otherwise call into MachineKeySection routines.

                if (_Protection == FormsProtectionEnum.All || _Protection == FormsProtectionEnum.Encryption) {
                    // DevDiv Bugs 137864: Include a random IV if under the right compat mode
                    // for improved encryption semantics
                    bBlob = MachineKeySection.EncryptOrDecryptData(false, bBlob, null, 0, bBlob.Length, false, false, IVType.Random);
                    if (bBlob == null)
                        return null;
                }

                ticketLength = bBlob.Length;

                if (_Protection == FormsProtectionEnum.All || _Protection == FormsProtectionEnum.Validation) {
                    if (!MachineKeySection.VerifyHashedData(bBlob))
                        return null;
                    ticketLength -= MachineKeySection.HashSize;
                }
#pragma warning restore 618 // calling obsolete methods
            }

            //////////////////////////////////////////////////////////////////////
            // Step 4: Change binary ticket to managed struct

            // ** MSRC 11838 **
            // Framework20 / Framework40 ticket generation modes are insecure. We should use a
            // secure serialization mode by default.
            if (!AppSettings.UseLegacyFormsAuthenticationTicketCompatibility) {
                return FormsAuthenticationTicketSerializer.Deserialize(bBlob, ticketLength);
            }

            // ** MSRC 11838 **
            // If we have reached this point of execution, the developer has explicitly elected
            // to continue using the insecure code path instead of the secure one. We removed
            // the Framework40 serialization mode, so everybody using the legacy code path is
            // forced to Framework20.

            int iSize = ((ticketLength > MAX_TICKET_LENGTH) ? MAX_TICKET_LENGTH : ticketLength);
            StringBuilder name = new StringBuilder(iSize);
            StringBuilder data = new StringBuilder(iSize);
            StringBuilder path = new StringBuilder(iSize);
            byte[] pBin = new byte[4];
            long[] pDates = new long[2];

            int iRet = UnsafeNativeMethods.CookieAuthParseTicket(bBlob, ticketLength,
                                                                   name, iSize,
                                                                   data, iSize,
                                                                   path, iSize,
                                                                   pBin, pDates);

            if (iRet != 0)
                return null;

            DateTime dt1 = DateTime.FromFileTime(pDates[0]);
            DateTime dt2 = DateTime.FromFileTime(pDates[1]);

            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket((int)pBin[0],
                                                     name.ToString(),
                                                     dt1,
                                                     dt2,
                                                     (bool)(pBin[1] != 0),
                                                     data.ToString(),
                                                     path.ToString());
            return ticket;
        }


        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        // Encrypt a ticket

        /// <devdoc>
        ///    Given a FormsAuthenticationTicket, this
        ///    method produces a string containing an encrypted authentication ticket suitable
        ///    for use in an HTTP cookie.
        /// </devdoc>
        public static String Encrypt(FormsAuthenticationTicket ticket)
        {
            return Encrypt(ticket, true);
        }
        internal static String Encrypt(FormsAuthenticationTicket ticket, bool hexEncodedTicket)
        {
            if (ticket == null)
                throw new ArgumentNullException("ticket");

            Initialize();
            //////////////////////////////////////////////////////////////////////
            // Step 1a: Make it into a binary blob
            byte[] bBlob = MakeTicketIntoBinaryBlob(ticket);
            if (bBlob == null)
                return null;

            //////////////////////////////////////////////////////////////////////
            // Step 1b: If new crypto routines are enabled, call them instead.
            if (AspNetCryptoServiceProvider.Instance.IsDefaultProvider) {
                ICryptoService cryptoService = AspNetCryptoServiceProvider.Instance.GetCryptoService(Purpose.FormsAuthentication_Ticket);
                byte[] protectedData = cryptoService.Protect(bBlob);
                bBlob = protectedData;
            } else {
#pragma warning disable 618 // calling obsolete methods
                // otherwise..

                //////////////////////////////////////////////////////////////////////
                // Step 2: Get the MAC and add to the blob
                if (_Protection == FormsProtectionEnum.All || _Protection == FormsProtectionEnum.Validation) {
                    byte[] bMac = MachineKeySection.HashData(bBlob, null, 0, bBlob.Length);
                    if (bMac == null)
                        return null;
                    byte[] bAll = new byte[bMac.Length + bBlob.Length];
                    Buffer.BlockCopy(bBlob, 0, bAll, 0, bBlob.Length);
                    Buffer.BlockCopy(bMac, 0, bAll, bBlob.Length, bMac.Length);
                    bBlob = bAll;
                }

                if (_Protection == FormsProtectionEnum.All || _Protection == FormsProtectionEnum.Encryption) {
                    //////////////////////////////////////////////////////////////////////
                    // Step 3: Do the actual encryption
                    // DevDiv Bugs 137864: Include a random IV if under the right compat mode
                    // for improved encryption semantics
                    bBlob = MachineKeySection.EncryptOrDecryptData(true, bBlob, null, 0, bBlob.Length, false, false, IVType.Random);
                }
#pragma warning restore 618 // calling obsolete methods
            }

            //if (!hexEncodedTicket)
            //    return HttpServerUtility.UrlTokenEncode(bBlob);
            //else
                return CryptoUtil.BinaryToHex(bBlob);
        }

        public static String FormsCookiePath { get { Initialize(); return _FormsCookiePath; } }


        //public static TicketCompatibilityMode TicketCompatibilityMode { get { Initialize(); return _TicketCompatibilityMode; } }


        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        // Private stuff

        /////////////////////////////////////////////////////////////////////////////
        // Config Tags
        private const String CONFIG_DEFAULT_COOKIE = ".ASPXAUTH";

        /////////////////////////////////////////////////////////////////////////////
        // Private data
        private static bool _Initialized;
        private static FormsProtectionEnum _Protection;
        private static String _FormsCookiePath;
        private static string _CookieDomain = null;
        //private static TicketCompatibilityMode _TicketCompatibilityMode;

        /////////////////////////////////////////////////////////////////////////////
        private static byte[] MakeTicketIntoBinaryBlob(FormsAuthenticationTicket ticket)
        {
            // None of the modes (Framework20 / Framework40 / beyond) support null values for these fields;
            // they always eventually just returned a null value.
            if (ticket.Name == null || ticket.UserData == null || ticket.CookiePath == null) {
                return null;
            }

            // ** MSRC 11838 **
            // Framework20 / Framework40 ticket generation modes are insecure. We should use a
            // secure serialization mode by default.
            if (!AppSettings.UseLegacyFormsAuthenticationTicketCompatibility) {
                return FormsAuthenticationTicketSerializer.Serialize(ticket);
            }

            // ** MSRC 11838 **
            // If we have reached this point of execution, the developer has explicitly elected
            // to continue using the insecure code path instead of the secure one. We removed
            // the Framework40 serialization mode, so everybody using the legacy code path is
            // forced to Framework20.

            byte[] bData = new byte[4096];
            byte[] pBin = new byte[4];
            long[] pDates = new long[2];
            byte[] pNull = { 0, 0, 0 };

            // DevDiv Bugs 137864: 8 bytes may not be enough random bits as the length should be equal to the
            // key size. In CompatMode > Framework20SP1, use the IVType.Random feature instead of these 8 bytes,
            // but still include empty 8 bytes for compat with webengine.dll, where CookieAuthConstructTicket is.
            // Note that even in CompatMode = Framework20SP2 we fill 8 bytes with random data if the ticket
            // is not going to be encrypted.

            bool willEncrypt = (_Protection == FormsProtectionEnum.All || _Protection == FormsProtectionEnum.Encryption);
            bool legacyPadding = !willEncrypt || (MachineKeySection.CompatMode == MachineKeyCompatibilityMode.Framework20SP1);
            if (legacyPadding) {
                // Fill the first 8 bytes of the blob with random bits
                byte[] bRandom = new byte[8];
                RNGCryptoServiceProvider randgen = new RNGCryptoServiceProvider();
                randgen.GetBytes(bRandom);
                Buffer.BlockCopy(bRandom, 0, bData, 0, 8);
            } else {
                // use blank 8 bytes for compatibility with CookieAuthConstructTicket (do nothing)
            }

            pBin[0] = (byte)ticket.Version;
            pBin[1] = (byte)(ticket.IsPersistent ? 1 : 0);

            pDates[0] = ticket.IssueDate.ToFileTime();
            pDates[1] = ticket.Expiration.ToFileTime();

            int iRet = UnsafeNativeMethods.CookieAuthConstructTicket(
                        bData, bData.Length,
                        ticket.Name, ticket.UserData, ticket.CookiePath,
                        pBin, pDates);

            if (iRet < 0)
                return null;

            byte[] ciphertext = new byte[iRet];
            Buffer.BlockCopy(bData, 0, ciphertext, 0, iRet);
            return ciphertext;
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        static private void RemoveQSVar(ref string strUrl, int posQ, string token, string sep, int lenAtStartToLeave)
        {
            for (int pos = strUrl.LastIndexOf(token, StringComparison.Ordinal); pos >= posQ; pos = strUrl.LastIndexOf(token, StringComparison.Ordinal)) {
                int end = strUrl.IndexOf(sep, pos + token.Length, StringComparison.Ordinal) + sep.Length;
                if (end < sep.Length || end >= strUrl.Length) { // ending separator not found or nothing is at the end
                    strUrl = strUrl.Substring(0, pos);
                } else {
                    strUrl = strUrl.Substring(0, pos + lenAtStartToLeave) + strUrl.Substring(end);
                }
            }
        }

    }
}

