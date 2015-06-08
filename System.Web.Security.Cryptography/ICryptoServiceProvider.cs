using System;
namespace FormsAuthOnly.Security.Cryptography
{
	internal interface ICryptoServiceProvider
	{
		ICryptoService GetCryptoService(Purpose purpose, CryptoServiceOptions options = CryptoServiceOptions.None);
	}
}
