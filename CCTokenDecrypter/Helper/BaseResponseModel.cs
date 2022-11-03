using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace CCTokenDecrypter.Helper
{
    public class BaseResponseModel
    {
        public int Code { get; set; } = (int)HttpStatusCode.OK;
        public string Message { get; set; }
        public string Response { get; set; }
        public BaseResponseModel(string message, HttpStatusCode code = HttpStatusCode.OK, object response = null)
        {
            this.Code = (int)code;
            this.Message = message;
            this.Response = response == null ? "" : JObject.FromObject(response).ToString();
        }
    }
}
