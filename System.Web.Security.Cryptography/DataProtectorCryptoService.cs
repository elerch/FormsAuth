using System;
using System.Security.Cryptography;
namespace FormsAuthOnly.Security.Cryptography
{
	internal sealed class DataProtectorCryptoService : ICryptoService
	{
		private readonly IDataProtectorFactory _dataProtectorFactory;
		private readonly Purpose _purpose;
		public DataProtectorCryptoService(IDataProtectorFactory dataProtectorFactory, Purpose purpose)
		{
			this._dataProtectorFactory = dataProtectorFactory;
			this._purpose = purpose;
		}
		private byte[] PerformOperation(byte[] data, bool protect)
		{
			byte[] result;
			//using (new ApplicationImpersonationContext())
			{
				DataProtector dataProtector = null;
				try
				{
					dataProtector = this._dataProtectorFactory.GetDataProtector(this._purpose);
					result = (protect ? dataProtector.Protect(data) : dataProtector.Unprotect(data));
				}
				finally
				{
					IDisposable disposable = dataProtector as IDisposable;
					if (disposable != null)
					{
						disposable.Dispose();
					}
				}
			}
			return result;
		}
		public byte[] Protect(byte[] clearData)
		{
			return this.PerformOperation(clearData, true);
		}
		public byte[] Unprotect(byte[] protectedData)
		{
			return this.PerformOperation(protectedData, false);
		}
	}
}
