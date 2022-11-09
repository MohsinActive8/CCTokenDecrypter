using CCTokenDecrypter.Helper;
using CCTokenDecrypter.Models;
using CCTokenDecrypter.Utility;
using ClosedXML.Excel;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace CCTokenDecrypter.Controllers
{
    public class HomeController : Controller
    {
        public IConfiguration _configuration { get; set; }
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> UploadAndDecrypt(FIleUploadUIModel model)
        {
            try
            {
                List<ExcelModel> list = new List<ExcelModel>();

                #region read excel and parse into model
                using (MemoryStream stream = new MemoryStream())
                {
                    await model.XlsFile.CopyToAsync(stream);
                    using (XLWorkbook workbook = new XLWorkbook(stream))
                    {
                        // opening sheet from excel file
                        IXLWorksheet worksheet = workbook.Worksheet(1);

                        bool firstRow = true;
                        foreach (IXLRow row in worksheet.Rows())
                        {
                            if (firstRow)
                            {
                                firstRow = false;
                                continue;
                            }

                            list.Add(new ExcelModel
                            {
                                AccountID = Convert.ToInt32(row.Cell("A").Value.ToString()),
                                AccountWalletID = Convert.ToInt32(row.Cell("B").Value.ToString()),
                                CCName = row.Cell("C").Value.ToString().Trim(),
                                CCLastFour = row.Cell("D").Value.ToString().Trim(),
                                CCExpirationMonth = Convert.ToInt32(row.Cell("E").Value.ToString()),
                                CCExpirationYear = row.Cell("F").Value.ToString().Trim(),
                                CCNumber = row.Cell("G").Value.ToString().Trim(),
                                CCType = row.Cell("H").Value.ToString().Trim(),
                                State = row.Cell("I").Value.ToString().Trim(),
                                Country = row.Cell("J").Value.ToString().Trim(),
                                Address1 = row.Cell("K").Value.ToString().Trim(),
                                Address2 = row.Cell("L").Value.ToString().Trim(),
                                City = row.Cell("M").Value.ToString().Trim(),
                                Zip = row.Cell("N").Value.ToString().Trim()
                            });
                        }
                    }
                }
                #endregion

                string _key = model.DecryptionKey;
                List<ExcelModel> response =  ExcelModel.DecryptCCNumbers(list, _key);

                #region write excel
                using (XLWorkbook workbook = new XLWorkbook())
                {
                    // opening sheet from excel file
                    IXLWorksheet worksheet = workbook.AddWorksheet();

                    int r = 1;
                    worksheet.Cell(r, 1).Value = "AccountID";
                    worksheet.Cell(r, 2).Value = "AccountWalletID";
                    worksheet.Cell(r, 3).Value = "CCName";
                    worksheet.Cell(r, 4).Value = "CCLastFour";
                    worksheet.Cell(r, 5).Value = "CCExpirationMonth";
                    worksheet.Cell(r, 6).Value = "CCExpirationYear";
                    worksheet.Cell(r, 7).Value = "CCNumber";
                    worksheet.Cell(r, 8).Value = "DecryptedCCNumber";
                    worksheet.Cell(r, 9).Value = "CCType";
                    worksheet.Cell(r, 10).Value = "State";
                    worksheet.Cell(r, 11).Value = "Country";
                    worksheet.Cell(r, 12).Value = "Address1";
                    worksheet.Cell(r, 13).Value = "Address2";
                    worksheet.Cell(r, 14).Value = "City";
                    worksheet.Cell(r, 15).Value = "Zip";

                    foreach (ExcelModel resp in response)
                    {
                        r++;
                        worksheet.Cell(r, 1).Value = resp.AccountID;
                        worksheet.Cell(r, 2).Value = resp.AccountWalletID;
                        worksheet.Cell(r, 3).Value = resp.CCName;
                        worksheet.Cell(r, 4).Value = resp.CCLastFour;
                        worksheet.Cell(r, 5).Value = resp.CCExpirationMonth;
                        worksheet.Cell(r, 6).Value = resp.CCExpirationYear;
                        worksheet.Cell(r, 7).Value = resp.CCNumber;

                        worksheet.Cell(r, 8).SetValue<string>(resp.DecryptedCCNumber);

                        worksheet.Cell(r, 9).Value = resp.CCType;
                        worksheet.Cell(r, 10).Value = resp.State;
                        worksheet.Cell(r, 11).Value = resp.Country;
                        worksheet.Cell(r, 12).Value = resp.Address1;
                        worksheet.Cell(r, 13).Value = resp.Address2;
                        worksheet.Cell(r, 14).Value = resp.City;
                        worksheet.Cell(r, 15).Value = resp.Zip;
                    }
                    MemoryStream ms = new MemoryStream();
                    workbook.SaveAs(ms);
                    ms.Seek(0, SeekOrigin.Begin);
                    return File(ms, "APPLICATION/ectet-stream", $"result__{model.XlsFile.FileName}");
                }
                #endregion
            }
            catch (Exception ex)
            {
                Logger.Error(ex.Message);
                return Json(new BaseResponseModel("File Upload failed", System.Net.HttpStatusCode.InternalServerError));
            }
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
