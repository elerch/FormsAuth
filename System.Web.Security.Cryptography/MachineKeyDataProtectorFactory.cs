using System;
using System.Security.Cryptography;
using FormsAuthOnly.Configuration;
namespace FormsAuthOnly.Security.Cryptography
{
	internal sealed class MachineKeyDataProtectorFactory : IDataProtectorFactory
	{
		private static readonly Purpose _creationTestingPurpose = new Purpose("test-1", new string[]
		{
			"test-2",
			"test-3"
		});
		private Func<Purpose, DataProtector> _dataProtectorFactory;
		private readonly MachineKeySection _machineKeySection;
		public MachineKeyDataProtectorFactory(MachineKeySection machineKeySection)
		{
			this._machineKeySection = machineKeySection;
		}
		public DataProtector GetDataProtector(Purpose purpose)
		{
			if (this._dataProtectorFactory == null)
			{
				this._dataProtectorFactory = this.GetDataProtectorFactory();
			}
			return this._dataProtectorFactory(purpose);
		}
		private Func<Purpose, DataProtector> GetDataProtectorFactory()
		{
			string applicationName = this._machineKeySection.ApplicationName;
			string dataProtectorTypeName = this._machineKeySection.DataProtectorType;
			Func<Purpose, DataProtector> func = delegate(Purpose purpose)
			{
				DataProtector result;
				//using (new ApplicationImpersonationContext())
				{
					result = DataProtector.Create(dataProtectorTypeName, applicationName, purpose.PrimaryPurpose, purpose.SpecificPurposes);
				}
				return result;
			};
			Exception innerException = null;
			try
			{
				DataProtector dataProtector = func(MachineKeyDataProtectorFactory._creationTestingPurpose);
				if (dataProtector != null)
				{
					IDisposable disposable = dataProtector as IDisposable;
					if (disposable != null)
					{
						disposable.Dispose();
					}
					return func;
				}
			}
			catch (Exception)
			{
			}
			throw new InvalidOperationException(SR.GetString("MachineKeyDataProtectorFactory_FactoryCreationFailed"), innerException);
		}
	}
}
