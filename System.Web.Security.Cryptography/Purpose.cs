using System;
using System.Collections.Generic;
using System.IO;
namespace FormsAuthOnly.Security.Cryptography
{
	internal sealed class Purpose
	{
		public static readonly Purpose AnonymousIdentificationModule_Ticket = new Purpose("AnonymousIdentificationModule.Ticket", new string[0]);
		public static readonly Purpose AssemblyResourceLoader_WebResourceUrl = new Purpose("AssemblyResourceLoader.WebResourceUrl", new string[0]);
		public static readonly Purpose FormsAuthentication_Ticket = new Purpose("FormsAuthentication.Ticket", new string[0]);
		public static readonly Purpose WebForms_Page_PreviousPageID = new Purpose("WebForms.Page.PreviousPageID", new string[0]);
		public static readonly Purpose RolePrincipal_Ticket = new Purpose("RolePrincipal.Ticket", new string[0]);
		public static readonly Purpose ScriptResourceHandler_ScriptResourceUrl = new Purpose("ScriptResourceHandler.ScriptResourceUrl", new string[0]);
		public static readonly Purpose WebForms_ClientScriptManager_EventValidation = new Purpose("WebForms.ClientScriptManager.EventValidation", new string[0]);
		public static readonly Purpose WebForms_DetailsView_KeyTable = new Purpose("WebForms.DetailsView.KeyTable", new string[0]);
		public static readonly Purpose WebForms_GridView_DataKeys = new Purpose("WebForms.GridView.DataKeys", new string[0]);
		public static readonly Purpose WebForms_GridView_SortExpression = new Purpose("WebForms.GridView.SortExpression", new string[0]);
		public static readonly Purpose WebForms_HiddenFieldPageStatePersister_ClientState = new Purpose("WebForms.HiddenFieldPageStatePersister.ClientState", new string[0]);
		public static readonly Purpose WebForms_ScriptManager_HistoryState = new Purpose("WebForms.ScriptManager.HistoryState", new string[0]);
		public static readonly Purpose WebForms_SessionPageStatePersister_ClientState = new Purpose("WebForms.SessionPageStatePersister.ClientState", new string[0]);
		public static readonly Purpose User_MachineKey_Protect = new Purpose("User.MachineKey.Protect", new string[0]);
		public static readonly Purpose User_ObjectStateFormatter_Serialize = new Purpose("User.ObjectStateFormatter.Serialize", new string[0]);
		public readonly string PrimaryPurpose;
		public readonly string[] SpecificPurposes;
		private byte[] _derivedKeyLabel;
		private byte[] _derivedKeyContext;
		internal CryptographicKey DerivedEncryptionKey
		{
			get;
			private set;
		}
		internal CryptographicKey DerivedValidationKey
		{
			get;
			private set;
		}
		internal bool SaveDerivedKeys
		{
			get;
			set;
		}
		public Purpose(string primaryPurpose, params string[] specificPurposes) : this(primaryPurpose, specificPurposes, null, null)
		{
		}
		internal Purpose(string primaryPurpose, string[] specificPurposes, CryptographicKey derivedEncryptionKey, CryptographicKey derivedValidationKey)
		{
			this.PrimaryPurpose = primaryPurpose;
			this.SpecificPurposes = (specificPurposes ?? new string[0]);
			this.DerivedEncryptionKey = derivedEncryptionKey;
			this.DerivedValidationKey = derivedValidationKey;
			this.SaveDerivedKeys = (this.SpecificPurposes.Length == 0);
		}
		internal Purpose AppendSpecificPurpose(string specificPurpose)
		{
			string[] array = new string[this.SpecificPurposes.Length + 1];
			Array.Copy(this.SpecificPurposes, array, this.SpecificPurposes.Length);
			string[] expr_25 = array;
			expr_25[expr_25.Length - 1] = specificPurpose;
			return new Purpose(this.PrimaryPurpose, array);
		}
		internal Purpose AppendSpecificPurposes(IList<string> specificPurposes)
		{
			if (specificPurposes == null || specificPurposes.Count == 0)
			{
				return this;
			}
			string[] array = new string[this.SpecificPurposes.Length + specificPurposes.Count];
			Array.Copy(this.SpecificPurposes, array, this.SpecificPurposes.Length);
			specificPurposes.CopyTo(array, this.SpecificPurposes.Length);
			return new Purpose(this.PrimaryPurpose, array);
		}
		public CryptographicKey GetDerivedEncryptionKey(IMasterKeyProvider masterKeyProvider, KeyDerivationFunction keyDerivationFunction)
		{
			CryptographicKey cryptographicKey = this.DerivedEncryptionKey;
			if (cryptographicKey == null)
			{
				CryptographicKey encryptionKey = masterKeyProvider.GetEncryptionKey();
				cryptographicKey = keyDerivationFunction(encryptionKey, this);
				if (this.SaveDerivedKeys)
				{
					this.DerivedEncryptionKey = cryptographicKey;
				}
			}
			return cryptographicKey;
		}
		public CryptographicKey GetDerivedValidationKey(IMasterKeyProvider masterKeyProvider, KeyDerivationFunction keyDerivationFunction)
		{
			CryptographicKey cryptographicKey = this.DerivedValidationKey;
			if (cryptographicKey == null)
			{
				CryptographicKey validationKey = masterKeyProvider.GetValidationKey();
				cryptographicKey = keyDerivationFunction(validationKey, this);
				if (this.SaveDerivedKeys)
				{
					this.DerivedValidationKey = cryptographicKey;
				}
			}
			return cryptographicKey;
		}
		internal void GetKeyDerivationParameters(out byte[] label, out byte[] context)
		{
			if (this._derivedKeyLabel == null)
			{
				this._derivedKeyLabel = CryptoUtil.SecureUTF8Encoding.GetBytes(this.PrimaryPurpose);
			}
			if (this._derivedKeyContext == null)
			{
				using (MemoryStream memoryStream = new MemoryStream())
				{
					using (BinaryWriter binaryWriter = new BinaryWriter(memoryStream, CryptoUtil.SecureUTF8Encoding))
					{
						string[] specificPurposes = this.SpecificPurposes;
						for (int i = 0; i < specificPurposes.Length; i++)
						{
							string value = specificPurposes[i];
							binaryWriter.Write(value);
						}
						this._derivedKeyContext = memoryStream.ToArray();
					}
				}
			}
			label = this._derivedKeyLabel;
			context = this._derivedKeyContext;
		}
	}
}
