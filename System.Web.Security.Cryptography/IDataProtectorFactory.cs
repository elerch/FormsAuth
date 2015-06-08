using System;
using System.Security.Cryptography;
namespace FormsAuthOnly.Security.Cryptography
{
	internal interface IDataProtectorFactory
	{
		DataProtector GetDataProtector(Purpose purpose);
	}
}
