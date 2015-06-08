using System;
using System.Security.Cryptography;
namespace FormsAuthOnly.Security.Cryptography
{
	internal static class CryptoAlgorithms
	{
		internal static Aes CreateAes()
		{
			return new AesCryptoServiceProvider();
		}
		[Obsolete("DES is deprecated and MUST NOT be used by new features. Consider using AES instead.")]
		internal static DES CreateDES()
		{
			return new DESCryptoServiceProvider();
		}
		internal static HMACSHA1 CreateHMACSHA1()
		{
			return new HMACSHA1();
		}
		internal static HMACSHA256 CreateHMACSHA256()
		{
			return new HMACSHA256();
		}
		internal static HMACSHA384 CreateHMACSHA384()
		{
			return new HMACSHA384();
		}
		internal static HMACSHA512 CreateHMACSHA512()
		{
			return new HMACSHA512();
		}
		internal static HMACSHA512 CreateHMACSHA512(byte[] key)
		{
			return new HMACSHA512(key);
		}
		[Obsolete("MD5 is deprecated and MUST NOT be used by new features. Consider using a SHA-2 algorithm instead.")]
		internal static MD5 CreateMD5()
		{
			return new MD5Cng();
		}
		[Obsolete("SHA1 is deprecated and MUST NOT be used by new features. Consider using a SHA-2 algorithm instead.")]
		internal static SHA1 CreateSHA1()
		{
			return new SHA1Cng();
		}
		internal static SHA256 CreateSHA256()
		{
			return new SHA256Cng();
		}
		[Obsolete("3DES is deprecated and MUST NOT be used by new features. Consider using AES instead.")]
		internal static TripleDES CreateTripleDES()
		{
			return new TripleDESCryptoServiceProvider();
		}
	}
}
