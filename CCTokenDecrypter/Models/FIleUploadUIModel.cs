using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;
using CCTokenDecrypter.Helper;

namespace CCTokenDecrypter.Models
{
    public class FIleUploadUIModel
    {
        [Required(), Display(Name = "Excel File"), AllowedExtensions(new string[] { ".xls", ".xlsx" })]
        public IFormFile XlsFile { get; set; }
        [Required(), Display(Name = "Decryption Key")]
        public string DecryptionKey { get; set; }
    }
}
