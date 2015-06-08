using System;
using System.Runtime.Serialization;
namespace FormsAuthOnly.Security
{
	[Serializable]
	public sealed class FormsAuthenticationTicket
	{
		private int _Version;
		private string _Name;
		private DateTime _Expiration;
		private DateTime _IssueDate;
		private bool _IsPersistent;
		private string _UserData;
		private string _CookiePath;
		[OptionalField(VersionAdded = 2)]
		private int _InternalVersion;
		[OptionalField(VersionAdded = 2)]
		private byte[] _InternalData;
		[NonSerialized]
		private bool _ExpirationUtcHasValue;
		[NonSerialized]
		private DateTime _ExpirationUtc;
		[NonSerialized]
		private bool _IssueDateUtcHasValue;
		[NonSerialized]
		private DateTime _IssueDateUtc;
		public int Version
		{
			get
			{
				return this._Version;
			}
		}
		public string Name
		{
			get
			{
				return this._Name;
			}
		}
		public DateTime Expiration
		{
			get
			{
				return this._Expiration;
			}
		}
		public DateTime IssueDate
		{
			get
			{
				return this._IssueDate;
			}
		}
		public bool IsPersistent
		{
			get
			{
				return this._IsPersistent;
			}
		}
		public bool Expired
		{
			get
			{
				return this.ExpirationUtc < DateTime.UtcNow;
			}
		}
		public string UserData
		{
			get
			{
				return this._UserData;
			}
		}
		public string CookiePath
		{
			get
			{
				return this._CookiePath;
			}
		}
		internal DateTime ExpirationUtc
		{
			get
			{
				if (!this._ExpirationUtcHasValue)
				{
					return this.Expiration.ToUniversalTime();
				}
				return this._ExpirationUtc;
			}
		}
		internal DateTime IssueDateUtc
		{
			get
			{
				if (!this._IssueDateUtcHasValue)
				{
					return this.IssueDate.ToUniversalTime();
				}
				return this._IssueDateUtc;
			}
		}
		public FormsAuthenticationTicket(int version, string name, DateTime issueDate, DateTime expiration, bool isPersistent, string userData)
		{
			this._Version = version;
			this._Name = name;
			this._Expiration = expiration;
			this._IssueDate = issueDate;
			this._IsPersistent = isPersistent;
			this._UserData = userData;
			this._CookiePath = FormsAuthentication.FormsCookiePath;
		}
		public FormsAuthenticationTicket(int version, string name, DateTime issueDate, DateTime expiration, bool isPersistent, string userData, string cookiePath)
		{
			this._Version = version;
			this._Name = name;
			this._Expiration = expiration;
			this._IssueDate = issueDate;
			this._IsPersistent = isPersistent;
			this._UserData = userData;
			this._CookiePath = cookiePath;
		}
		public FormsAuthenticationTicket(string name, bool isPersistent, int timeout)
		{
			this._Version = 2;
			this._Name = name;
			this._IssueDateUtcHasValue = true;
			this._IssueDateUtc = DateTime.UtcNow;
			this._IssueDate = DateTime.Now;
			this._IsPersistent = isPersistent;
			this._UserData = "";
			this._ExpirationUtcHasValue = true;
			this._ExpirationUtc = this._IssueDateUtc.AddMinutes((double)timeout);
			this._Expiration = this._IssueDate.AddMinutes((double)timeout);
			this._CookiePath = FormsAuthentication.FormsCookiePath;
		}
		internal static FormsAuthenticationTicket FromUtc(int version, string name, DateTime issueDateUtc, DateTime expirationUtc, bool isPersistent, string userData, string cookiePath)
		{
			return new FormsAuthenticationTicket(version, name, issueDateUtc.ToLocalTime(), expirationUtc.ToLocalTime(), isPersistent, userData, cookiePath)
			{
				_IssueDateUtcHasValue = true,
				_IssueDateUtc = issueDateUtc,
				_ExpirationUtcHasValue = true,
				_ExpirationUtc = expirationUtc
			};
		}
	}
}
