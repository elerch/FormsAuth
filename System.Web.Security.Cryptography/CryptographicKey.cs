using System;
namespace FormsAuthOnly.Security.Cryptography
{
	internal sealed class CryptographicKey
	{
		private readonly byte[] _keyMaterial;
		public int KeyLength
		{
			get
			{
				return checked(this._keyMaterial.Length * 8);
			}
		}
		public CryptographicKey(byte[] keyMaterial)
		{
			this._keyMaterial = keyMaterial;
		}
		public CryptographicKey ExtractBits(int offset, int count)
		{
			int srcOffset = offset / 8;
			int num = count / 8;
			byte[] array = new byte[num];
			Buffer.BlockCopy(this._keyMaterial, srcOffset, array, 0, num);
			return new CryptographicKey(array);
		}
		public byte[] GetKeyMaterial()
		{
			return this._keyMaterial;
		}
	}
}
