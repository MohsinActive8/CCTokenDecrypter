using CCTokenDecrypter.Utility;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CCTokenDecrypter.Models
{
    public class ExcelModel
    {
        public int AccountID { get; set; }
        public int AccountWalletID { get; set; }
        public string? CCName { get; set; }
        public string CCLastFour { get; set; }
        public int CCExpirationMonth { get; set; }
        public string CCExpirationYear { get; set; }
        public string CCNumber { get; set; }
        public string? CCType { get; set; }
        public string? State { get; set; }
        public string? Country { get; set; }
        public string? Address1 { get; set; }
        public string? Address2 { get; set; }
        public string? City { get; set; }
        public string? Zip { get; set; }

        public string? DecryptedCCNumber { get; set; } = string.Empty;



        public static List<ExcelModel> DecryptCCNumbers(List<ExcelModel> list, string decKey)
        {
            try
            {
                foreach(ExcelModel x in list)
                {
                    x.DecryptedCCNumber = Security.Decrypt(x.CCNumber, decKey);
                }
                return list;
            }
            catch (Exception ex)
            {
                Logger.Error(ex.Message);
                return null;
            }
        }
    }
}
