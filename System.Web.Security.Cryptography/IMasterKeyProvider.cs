using System;
namespace FormsAuthOnly.Security.Cryptography
{
	internal interface IMasterKeyProvider
	{
		CryptographicKey GetEncryptionKey();
		CryptographicKey GetValidationKey();
	}
}
