using System;
using System.IO;
using System.Security.Cryptography;
namespace FormsAuthOnly.Security.Cryptography
{
	internal sealed class NetFXCryptoService : ICryptoService
	{
		private readonly ICryptoAlgorithmFactory _cryptoAlgorithmFactory;
		private readonly CryptographicKey _encryptionKey;
		private readonly bool _predictableIV;
		private readonly CryptographicKey _validationKey;
		public NetFXCryptoService(ICryptoAlgorithmFactory cryptoAlgorithmFactory, CryptographicKey encryptionKey, CryptographicKey validationKey, bool predictableIV = false)
		{
			this._cryptoAlgorithmFactory = cryptoAlgorithmFactory;
			this._encryptionKey = encryptionKey;
			this._validationKey = validationKey;
			this._predictableIV = predictableIV;
		}
		public byte[] Protect(byte[] clearData)
		{
			byte[] result;
			using (SymmetricAlgorithm encryptionAlgorithm = this._cryptoAlgorithmFactory.GetEncryptionAlgorithm())
			{
				encryptionAlgorithm.Key = this._encryptionKey.GetKeyMaterial();
				if (this._predictableIV)
				{
					encryptionAlgorithm.IV = CryptoUtil.CreatePredictableIV(clearData, encryptionAlgorithm.BlockSize);
				}
				else
				{
					encryptionAlgorithm.GenerateIV();
				}
				byte[] iV = encryptionAlgorithm.IV;
				using (MemoryStream memoryStream = new MemoryStream())
				{
					memoryStream.Write(iV, 0, iV.Length);
					using (ICryptoTransform cryptoTransform = encryptionAlgorithm.CreateEncryptor())
					{
						using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
						{
							cryptoStream.Write(clearData, 0, clearData.Length);
							cryptoStream.FlushFinalBlock();
							using (KeyedHashAlgorithm validationAlgorithm = this._cryptoAlgorithmFactory.GetValidationAlgorithm())
							{
								validationAlgorithm.Key = this._validationKey.GetKeyMaterial();
								byte[] array = validationAlgorithm.ComputeHash(memoryStream.GetBuffer(), 0, checked((int)memoryStream.Length));
								memoryStream.Write(array, 0, array.Length);
								result = memoryStream.ToArray();
							}
						}
					}
				}
			}
			return result;
		}
		public byte[] Unprotect(byte[] protectedData)
		{
			checked
			{
				byte[] result;
				using (SymmetricAlgorithm encryptionAlgorithm = this._cryptoAlgorithmFactory.GetEncryptionAlgorithm())
				{
					encryptionAlgorithm.Key = this._encryptionKey.GetKeyMaterial();
					using (KeyedHashAlgorithm validationAlgorithm = this._cryptoAlgorithmFactory.GetValidationAlgorithm())
					{
						validationAlgorithm.Key = this._validationKey.GetKeyMaterial();
						int num = encryptionAlgorithm.BlockSize / 8;
						int num2 = validationAlgorithm.HashSize / 8;
						int num3 = protectedData.Length - num - num2;
						if (num3 <= 0)
						{
							result = null;
						}
						else
						{
							byte[] array = validationAlgorithm.ComputeHash(protectedData, 0, num + num3);
							if (!CryptoUtil.BuffersAreEqual(protectedData, num + num3, num2, array, 0, array.Length))
							{
								result = null;
							}
							else
							{
								byte[] array2 = new byte[num];
								Buffer.BlockCopy(protectedData, 0, array2, 0, array2.Length);
								encryptionAlgorithm.IV = array2;
								using (MemoryStream memoryStream = new MemoryStream())
								{
									using (ICryptoTransform cryptoTransform = encryptionAlgorithm.CreateDecryptor())
									{
										using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
										{
											cryptoStream.Write(protectedData, num, num3);
											cryptoStream.FlushFinalBlock();
											result = memoryStream.ToArray();
										}
									}
								}
							}
						}
					}
				}
				return result;
			}
		}
	}
}
