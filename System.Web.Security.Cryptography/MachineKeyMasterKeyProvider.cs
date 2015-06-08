using System;
using System.Collections.Generic;
using System.Diagnostics;
using FormsAuthOnly.Configuration;
namespace FormsAuthOnly.Security.Cryptography
{
	internal sealed class MachineKeyMasterKeyProvider : IMasterKeyProvider
	{
		private const int AUTOGEN_ENCRYPTION_OFFSET = 0;
		private const int AUTOGEN_ENCRYPTION_KEYLENGTH = 256;
		private const int AUTOGEN_VALIDATION_OFFSET = 256;
		private const int AUTOGEN_VALIDATION_KEYLENGTH = 256;
		private const string AUTOGEN_KEYDERIVATION_PRIMARYPURPOSE = "MachineKeyDerivation";
		private const string AUTOGEN_KEYDERIVATION_ISOLATEAPPS_SPECIFICPURPOSE = "IsolateApps";
		private const string AUTOGEN_KEYDERIVATION_ISOLATEBYAPPID_SPECIFICPURPOSE = "IsolateByAppId";
		private string _applicationId;
		private string _applicationName;
		private CryptographicKey _autogenKeys;
		private CryptographicKey _encryptionKey;
		private KeyDerivationFunction _keyDerivationFunction;
		private readonly MachineKeySection _machineKeySection;
		private CryptographicKey _validationKey;
		internal string ApplicationName
		{
			get
			{
				if (this._applicationName == null)
				{
					this._applicationName = /*(HttpRuntime.AppDomainAppVirtualPath ?? */Process.GetCurrentProcess().MainModule.ModuleName;
				}
				return this._applicationName;
			}
		}
		internal string ApplicationId
		{
			get
			{
				//if (this._applicationId == null)
				//{
				//	this._applicationId = HttpRuntime.AppDomainAppId;
				//}
				return this._applicationId;
			}
		}
		internal CryptographicKey AutogenKeys
		{
			get
			{
				if (this._autogenKeys == null)
				{
                    throw new NotImplementedException();
					//this._autogenKeys = new CryptographicKey(HttpRuntime.s_autogenKeys);
				}
				return this._autogenKeys;
			}
		}
		internal KeyDerivationFunction KeyDerivationFunction
		{
			get
			{
				if (this._keyDerivationFunction == null)
				{
					this._keyDerivationFunction = new KeyDerivationFunction(SP800_108.DeriveKey);
				}
				return this._keyDerivationFunction;
			}
		}
		internal MachineKeyMasterKeyProvider(MachineKeySection machineKeySection, string applicationId = null, string applicationName = null, CryptographicKey autogenKeys = null, KeyDerivationFunction keyDerivationFunction = null)
		{
			this._machineKeySection = machineKeySection;
			this._applicationId = applicationId;
			this._applicationName = applicationName;
			this._autogenKeys = autogenKeys;
			this._keyDerivationFunction = keyDerivationFunction;
		}
		private static void AddSpecificPurposeString(IList<string> specificPurposes, string key, string value)
		{
			specificPurposes.Add(key + ": " + value);
		}
		private CryptographicKey GenerateCryptographicKey(string configAttributeName, string configAttributeValue, int autogenKeyOffset, int autogenKeyCount, string errorResourceString)
		{
			byte[] array = CryptoUtil.HexToBinary(configAttributeValue);
			if (array != null && array.Length != 0)
			{
				return new CryptographicKey(array);
			}
			bool flag = false;
			bool flag2 = false;
			bool flag3 = false;
			if (configAttributeValue != null)
			{
				string[] array2 = configAttributeValue.Split(new char[]
				{
					','
				});
				for (int i = 0; i < array2.Length; i++)
				{
					string a = array2[i];
					if (!(a == "AutoGenerate"))
					{
						if (!(a == "IsolateApps"))
						{
							if (!(a == "IsolateByAppId"))
							{
								throw new InvalidOperationException(SR.GetString(errorResourceString), null);
							}
							flag3 = true;
						}
						else
						{
							flag2 = true;
						}
					}
					else
					{
						flag = true;
					}
				}
			}
			if (!flag)
			{
				throw new InvalidOperationException(SR.GetString(errorResourceString), null);
			}
			CryptographicKey keyDerivationKey = this.AutogenKeys.ExtractBits(autogenKeyOffset, autogenKeyCount);
			List<string> list = new List<string>();
			if (flag2)
			{
				MachineKeyMasterKeyProvider.AddSpecificPurposeString(list, "IsolateApps", this.ApplicationName);
			}
			if (flag3)
			{
				MachineKeyMasterKeyProvider.AddSpecificPurposeString(list, "IsolateByAppId", this.ApplicationId);
			}
			Purpose purpose = new Purpose("MachineKeyDerivation", list.ToArray());
			return this.KeyDerivationFunction(keyDerivationKey, purpose);
		}
		public CryptographicKey GetEncryptionKey()
		{
			if (this._encryptionKey == null)
			{
				this._encryptionKey = this.GenerateCryptographicKey("decryptionKey", this._machineKeySection.DecryptionKey, 0, 256, "Invalid_decryption_key");
			}
			return this._encryptionKey;
		}
		public CryptographicKey GetValidationKey()
		{
			if (this._validationKey == null)
			{
				this._validationKey = this.GenerateCryptographicKey("validationKey", this._machineKeySection.ValidationKey, 256, 256, "Invalid_validation_key");
			}
			return this._validationKey;
		}
	}
}
