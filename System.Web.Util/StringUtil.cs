//------------------------------------------------------------------------------
// <copyright file="StringUtil.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>                                                                
//------------------------------------------------------------------------------

/*
 * StringUtil class
 * 
 * Copyright (c) 1999 Microsoft Corporation
 */

namespace FormsAuthOnly.Util
{
    using System.Globalization;
    using System;


    /*
     * Various string handling utilities
     */
    internal static class StringUtil
    {

        internal static string CheckAndTrimString(string paramValue, string paramName, bool throwIfNull)
        {
            return CheckAndTrimString(paramValue, paramName, throwIfNull, -1);
        }

        internal static string CheckAndTrimString(string paramValue, string paramName,
                                                  bool throwIfNull, int lengthToCheck)
        {
            if (paramValue == null) {
                if (throwIfNull) {
                    throw new ArgumentNullException(paramName);
                }
                return null;
            }
            string trimmedValue = paramValue.Trim();
            if (trimmedValue.Length == 0) {
                throw new ArgumentException(
                    SR.GetString(SR.PersonalizationProviderHelper_TrimmedEmptyString,
                                                     paramName));
            }
            if (lengthToCheck > -1 && trimmedValue.Length > lengthToCheck) {
                throw new ArgumentException(
                    SR.GetString(SR.StringUtil_Trimmed_String_Exceed_Maximum_Length,
                                                     paramValue, paramName, lengthToCheck.ToString(CultureInfo.InvariantCulture)));
            }
            return trimmedValue;
        }


        /*
         * Determines if the first string ends with the second string.
         * Fast, non-culture aware.  
         */
        unsafe internal static bool StringEndsWith(string s1, string s2)
        {
            int offset = s1.Length - s2.Length;
            if (offset < 0) {
                return false;
            }

            fixed (char* pch1 = s1, pch2 = s2)
            {
                char* p1 = pch1 + offset, p2 = pch2;
                int c = s2.Length;
                while (c-- > 0) {
                    if (*p1++ != *p2++)
                        return false;
                }
            }

            return true;
        }
    }
}
