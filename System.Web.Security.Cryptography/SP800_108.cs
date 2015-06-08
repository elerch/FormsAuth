using System;
using System.Security.Cryptography;
namespace FormsAuthOnly.Security.Cryptography
{
	internal static class SP800_108
	{
		public static CryptographicKey DeriveKey(CryptographicKey keyDerivationKey, Purpose purpose)
		{
			CryptographicKey result;
			using (HMACSHA512 hMACSHA = CryptoAlgorithms.CreateHMACSHA512(keyDerivationKey.GetKeyMaterial()))
			{
				byte[] label;
				byte[] context;
				purpose.GetKeyDerivationParameters(out label, out context);
				result = new CryptographicKey(SP800_108.DeriveKeyImpl(hMACSHA, label, context, keyDerivationKey.KeyLength));
			}
			return result;
		}
		private static byte[] DeriveKeyImpl(HMAC hmac, byte[] label, byte[] context, int keyLengthInBits)
		{
			int num = (label != null) ? label.Length : 0;
			int num2 = (context != null) ? context.Length : 0;
			checked
			{
				byte[] array = new byte[4 + num + 1 + num2 + 4];
				if (num != 0)
				{
					Buffer.BlockCopy(label, 0, array, 4, num);
				}
				if (num2 != 0)
				{
					Buffer.BlockCopy(context, 0, array, 5 + num, num2);
				}
				SP800_108.WriteUInt32ToByteArrayBigEndian((uint)keyLengthInBits, array, 5 + num + num2);
				int num3 = 0;
				int i = keyLengthInBits / 8;
				byte[] array2 = new byte[i];
				uint num4 = 1u;
				while (i > 0)
				{
					SP800_108.WriteUInt32ToByteArrayBigEndian(num4, array, 0);
					byte[] array3 = hmac.ComputeHash(array);
					int num5 = Math.Min(i, array3.Length);
					Buffer.BlockCopy(array3, 0, array2, num3, num5);
					num3 += num5;
					i -= num5;
					num4 += 1u;
				}
				return array2;
			}
		}
		private static void WriteUInt32ToByteArrayBigEndian(uint value, byte[] buffer, int offset)
		{
			buffer[offset + 0] = (byte)(value >> 24);
			buffer[offset + 1] = (byte)(value >> 16);
			buffer[offset + 2] = (byte)(value >> 8);
			buffer[offset + 3] = (byte)value;
		}
	}
}
