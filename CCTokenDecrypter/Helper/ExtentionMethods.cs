using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CCTokenDecrypter.Helper
{
    public static class ExtentionMethods
    {
        /// <summary>
        /// Indicates whether the specified datetime is null or a min value.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string ToNormalString(this byte[] value)
        {
            StringBuilder sBuilder = new StringBuilder();

            foreach (byte b in value)
            {
                sBuilder.Append(b.ToString("x2"));
            }

            return sBuilder.ToString();
        }
    }
}
