using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace FormsAuthOnly
{
    [ComVisible(false), SuppressUnmanagedCodeSecurity]
	internal static class UnsafeNativeMethods
	{
        [DllImport(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\webengine4.dll")]
        internal static extern int CookieAuthParseTicket(byte[] pData, int iDataLen, StringBuilder szName, int iNameLen, StringBuilder szData, int iUserDataLen, StringBuilder szPath, int iPathLen, byte[] pBytes, long[] pDates);
        [DllImport(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\webengine4.dll")]
        internal static extern int CookieAuthConstructTicket(byte[] pData, int iDataLen, string szName, string szData, string szPath, byte[] pBytes, long[] pDates);
		[DllImport(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\webengine4.dll")]
		internal static extern int GetSHA1Hash(byte[] data, int dataSize, byte[] hash, int hashSize);
        [DllImport(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\webengine4.dll")]
		internal static extern int GetHMACSHA1Hash(byte[] data1, int dataOffset1, int dataSize1, byte[] data2, int dataSize2, byte[] innerKey, int innerKeySize, byte[] outerKey, int outerKeySize, byte[] hash, int hashSize);

	}
}
