using System;
using System.Security.Cryptography;
namespace FormsAuthOnly.Security.Cryptography
{
	internal interface ICryptoAlgorithmFactory
	{
		SymmetricAlgorithm GetEncryptionAlgorithm();
		KeyedHashAlgorithm GetValidationAlgorithm();
	}
}
