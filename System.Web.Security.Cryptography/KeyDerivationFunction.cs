using System;
namespace FormsAuthOnly.Security.Cryptography
{
	internal delegate CryptographicKey KeyDerivationFunction(CryptographicKey keyDerivationKey, Purpose purpose);
}
