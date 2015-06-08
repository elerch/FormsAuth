using System;
using System.Configuration;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Security;
namespace FormsAuthOnly
{
	[Serializable]
	public class HttpException : ExternalException
	{
		private const int FACILITY_WIN32 = 7;
		private int _httpCode;
		private int _webEventCode;
		public int WebEventCode
		{
			get
			{
				return this._webEventCode;
			}
			internal set
			{
				this._webEventCode = value;
			}
		}
		internal static int HResultFromLastError(int lastError)
		{
			int result;
			if (lastError < 0)
			{
				result = lastError;
			}
			else
			{
				result = ((lastError & 65535) | 458752 | -2147483648);
			}
			return result;
		}
		public static HttpException CreateFromLastError(string message)
		{
			return new HttpException(message, HttpException.HResultFromLastError(Marshal.GetLastWin32Error()));
		}
		public HttpException()
		{
		}
		public HttpException(string message) : base(message)
		{
		}
		internal HttpException(string message, Exception innerException, int code) : base(message, innerException)
		{
			this._webEventCode = code;
		}
		public HttpException(string message, int hr) : base(message)
		{
			base.HResult = hr;
		}
		public HttpException(string message, Exception innerException) : base(message, innerException)
		{
		}
		public HttpException(int httpCode, string message, Exception innerException) : base(message, innerException)
		{
			this._httpCode = httpCode;
		}
		public HttpException(int httpCode, string message) : base(message)
		{
			this._httpCode = httpCode;
		}
		public HttpException(int httpCode, string message, int hr) : base(message)
		{
			base.HResult = hr;
			this._httpCode = httpCode;
		}
		protected HttpException(SerializationInfo info, StreamingContext context) : base(info, context)
		{
			this._httpCode = info.GetInt32("_httpCode");
		}
		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
			info.AddValue("_httpCode", this._httpCode);
		}
		public int GetHttpCode()
		{
			return HttpException.GetHttpCodeForException(this);
		}
		internal static int GetHttpCodeForException(Exception e)
		{
			if (e is HttpException)
			{
				HttpException ex = (HttpException)e;
				if (ex._httpCode > 0)
				{
					return ex._httpCode;
				}
			}
			else
			{
				if (e is UnauthorizedAccessException)
				{
					return 401;
				}
				if (e is PathTooLongException)
				{
					return 414;
				}
			}
			if (e.InnerException != null)
			{
				return HttpException.GetHttpCodeForException(e.InnerException);
			}
			return 500;
		}
	}
}
