using System;
using System.Configuration;
using System.Security.Cryptography;
namespace FormsAuthOnly.Security.Cryptography
{
	internal sealed class HomogenizingCryptoServiceWrapper : ICryptoService
	{
		internal ICryptoService WrappedCryptoService
		{
			get;
			private set;
		}
		public HomogenizingCryptoServiceWrapper(ICryptoService wrapped)
		{
			this.WrappedCryptoService = wrapped;
		}
		private static byte[] HomogenizeErrors(Func<byte[], byte[]> func, byte[] input)
		{
			byte[] array = null;
			bool flag = false;
			byte[] result;
			try
			{
				array = func(input);
				result = array;
			}
			catch (ConfigurationException)
			{
				flag = true;
				throw;
			}
			finally
			{
				if (array == null && !flag)
				{
					throw new CryptographicException();
				}
			}
			return result;
		}
		public byte[] Protect(byte[] clearData)
		{
			return HomogenizingCryptoServiceWrapper.HomogenizeErrors(new Func<byte[], byte[]>(this.WrappedCryptoService.Protect), clearData);
		}
		public byte[] Unprotect(byte[] protectedData)
		{
			return HomogenizingCryptoServiceWrapper.HomogenizeErrors(new Func<byte[], byte[]>(this.WrappedCryptoService.Unprotect), protectedData);
		}
	}
}
