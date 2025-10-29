using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Management;
using System.ServiceProcess;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Reflection;

namespace CAS
{
    public static class Program
    {
        public static int winbuild = System.Diagnostics.FileVersionInfo.GetVersionInfo(Environment.SystemDirectory + @"\kernel32.dll").FileBuildPart;

        public static bool ShowAll = false;
        public static bool ShowDlv = false;
        public static bool ShowIID = false;
        public static bool Passive = false;
        public static bool NT6 = winbuild >= 6000;
        public static bool NT7 = winbuild >= 7600;
        public static bool NT8 = winbuild >= 9200;
        public static bool NT9 = winbuild >= 9600;
        public static bool Elevated = (new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator));
        public static bool ShowHeader = true;

        public static string line2 = "============================================================";
        public static string line3 = "____________________________________________________________";

        public static string wslp = "SoftwareLicensingProduct";
        public static string wsls = "SoftwareLicensingService";
        public static string oslp = "OfficeSoftwareProtectionProduct";
        public static string osls = "OfficeSoftwareProtectionService";
        public static string winApp = "55c92734-d682-4d71-983e-d6ec3f16059f";
        public static string o14App = "59a52881-a989-479d-af46-f275c6370663";
        public static string o15App = "0ff1ce15-a989-479d-af46-f275c6370663";
        public static string SLKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SL";
        public static string NSKeyPath = @"HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SL";
        public static string[] VLActTypes = new string[] {"All", "AD", "KMS", "Token"};
        public static bool isSub = false;

        public static bool checkSubscription()
        {
            bool testSub = false;
            using (StreamReader rdr = new StreamReader(Environment.SystemDirectory + @"\wbem\sppwmi.mof", System.Text.Encoding.Unicode))
            {
                string line;
                while ((line = rdr.ReadLine()) != null)
                {
                    if (line.Contains("SubscriptionType"))
                    {
                        testSub = true;
                        break;
                    }
                }
            }
            return testSub;
        }

        public static void echoWindows()
        {
            Console.WriteLine(line2);
            Console.WriteLine("===                   Windows Status                     ===");
            Console.WriteLine(line2);
            if (!ShowAll) {Console.WriteLine();}
        }

        public static void echoOffice()
        {
            if (!ShowHeader) {return;}
            if (ShowAll) {Console.WriteLine();}
            Console.WriteLine(line2);
            Console.WriteLine("===                   Office Status                      ===");
            Console.WriteLine(line2);
            if (!ShowAll) {Console.WriteLine();}
            ShowHeader = false;
        }

        public static void CheckOhook()
        {
            bool hooked = false;
            string[] paths = new string[] {"ProgramFiles", "ProgramFiles(x86)"};
            foreach (string V in new string[] {"15", "16"})
            {
                foreach (string P in paths)
                {
                    string target = (Environment.GetEnvironmentVariable(P) + @"\Microsoft Office\Office" + V);
                    if (Directory.Exists(target) && (Directory.GetFiles(target, "sppc*dll")).Length > 0)
                        hooked = true;
                }
            }
            foreach (string A in new string[] {"System", "SystemX86"})
            {
                foreach (string V in new string[] {"Office 15", "Office"})
                {
                    foreach (string P in paths)
                    {
                        string target = (Environment.GetEnvironmentVariable(P) + @"\Microsoft " + V + @"\root\vfs\" + A);
                        if (Directory.Exists(target) && (Directory.GetFiles(target, "sppc*dll")).Length > 0)
                            hooked = true;
                    }
                }
            }
            if (!hooked)
            {
                return;
            }
            if (ShowAll) {Console.WriteLine();}
            Console.WriteLine(line2);
            Console.WriteLine("===                Office Ohook Status                   ===");
            Console.WriteLine(line2);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\r\nOhook for permanent Office activation is installed.\r\nYou can ignore the below mentioned Office activation status.");
            Console.ResetColor();
            if (!ShowAll) {Console.WriteLine();}
        }
/*
#region vNextDiag
        public static void vNextDiagRun()
        {
            return;
        }
#endregion
*/

        internal static void ParseArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].Trim().ToLowerInvariant();
                switch (arg)
                {
                    case "/all":
                    case "-all":
                        ShowAll = true;
                        break;
                    case "/dlv":
                    case "-dlv":
                        ShowDlv = true;
                        ShowIID = true;
                        break;
                    case "/iid":
                    case "-iid":
                        ShowIID = true;
                        break;
                    case "/pass":
                    case "-pass":
                        Passive = true;
                        break;
                    default:
                        break;
                }
            }
        }

        public static void Main(string[] args)
        {
            if (winbuild < 2600)
            {
                Console.WriteLine("Minimum supported OS is Windows XP");
                return;
            }

            if (args.Length > 0)
            {
                ParseArguments(args);
            }

            string prevTlt = Console.Title;
            Console.Title = "Check Activation Status";

            if (ShowAll)
            {
                try
                {
                    Console.SetBufferSize(Console.BufferWidth, 3000);
                    if (!Passive) {Console.Clear();}
                }
                catch
                {
                }
            }

            if (winbuild >= 26000) {isSub = checkSubscription();}
            bool DllDigital = (winbuild >= 14393 && File.Exists(Environment.SystemDirectory + @"\EditionUpgradeManagerObj.dll"));
            bool DllSubscription = (winbuild >= 14393 && File.Exists(Environment.SystemDirectory + @"\Clipc.dll"));

            string offsvc = "osppsvc";
            string winsvc = "slsvc";
            if (NT7 || !NT6)
            {
                winsvc = "sppsvc";
            }

            bool WsppHook = Services.IsInstalled(winsvc);
            bool OsppHook = Services.IsInstalled(offsvc);

            if (WsppHook)
            {
                if (NT6 && !NT7 && !Elevated)
                {
                    if (String.IsNullOrEmpty(System.Diagnostics.Process.GetProcessesByName(winsvc)[0].ProcessName)) {WsppHook = false; Console.WriteLine("\r\nError: failed to start " + winsvc + " Service.\r\n");}
                }
                else
                {
                    try {Services.DoStart(winsvc);} catch {WsppHook = false; Console.WriteLine("\r\nError: failed to start " + winsvc + " Service.\r\n");}
                }
            }

            List<string> cW1nd0ws = new List<string>(), c0ff1ce15 = new List<string>(), c0ff1ce14 = new List<string>(), ospp15 = new List<string>(), ospp14 = new List<string>();

            if (WsppHook)
            {
                GetID(wslp, winApp, ref cW1nd0ws);
                GetID(wslp, o15App, ref c0ff1ce15);
                GetID(wslp, o14App, ref c0ff1ce14);
            }

            if (cW1nd0ws.Count > 0)
            {
                echoWindows();
                ParseList(wslp, wsls, cW1nd0ws);
            }
            else if (NT6)
            {
                echoWindows();
                Console.WriteLine("Error: product key not found.\r\n");
            }

            if (NT8)
            {
                if (ShowAll) {Console.WriteLine();}
                CLIC.Program.ClicRun(DllDigital, DllSubscription);
                Console.WriteLine(line3);
                if (!ShowAll) {Console.WriteLine();}
            }

            if (c0ff1ce15.Count > 0)
            {
                CheckOhook();
                echoOffice();
                ParseList(wslp, wsls, c0ff1ce15);
            }

            if (c0ff1ce14.Count > 0)
            {
                echoOffice();
                ParseList(wslp, wsls, c0ff1ce14);
            }

            if (OsppHook)
            {
                try {Services.DoStart(offsvc);} catch {OsppHook = false; Console.WriteLine("\r\nError: failed to start " + offsvc + " Service.\r\n");}
            }

            if (OsppHook)
            {
                GetID(oslp, o15App, ref ospp15);
                GetID(oslp, o14App, ref ospp14);
            }

            if (ospp15.Count > 0)
            {
                echoOffice();
                ParseList(oslp, osls, ospp15);
            }

            if (ospp14.Count > 0)
            {
                echoOffice();
                ParseList(oslp, osls, ospp14);
            }
/*
            if (NT7)
            {
                vNextDiagRun();
            }
*/
            if (!Passive)
            {
                Console.Write("\nPress <Enter> to exit:");
                Console.ReadLine();
            }
            Console.Title = prevTlt;
            return;
        }

#region WMI
        public static void GetID(string strSLP, string strAppId, ref List<string> arrIDs)
        {
            bool NT5 = (strSLP.Equals(wslp) && winbuild < 6001);
            string isAdd = NT5 == false ? " AND LicenseDependsOn <> NULL)" : ")";
            string noAdd = " AND LicenseDependsOn IS NULL)";
            string query = "SELECT ID FROM " + strSLP + " WHERE (ApplicationID='" + strAppId + "'" + " AND PartialProductKey";
            string fltr;
            string clause;
            if (ShowAll)
            {
                fltr = query + " IS NULL";
                clause = fltr + isAdd;
                CollectIDs(clause, ref arrIDs);
                if (!NT5)
                {
                    clause = fltr + noAdd;
                    CollectIDs(clause, ref arrIDs);
                }
            }
            fltr = query + " <> NULL";
            clause = fltr + isAdd;
            CollectIDs(clause, ref arrIDs);
            if (!NT5)
            {
                clause = fltr + noAdd;
                CollectIDs(clause, ref arrIDs);
            }
        }

        public static void CollectIDs(string filter, ref List<string> arrIDs)
        {
            ManagementObjectCollection results;
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(filter))
            {
                try {results = searcher.Get();} catch {return;}
                if (results.Count > 0)
                {
                    foreach (ManagementObject queryObj in results)
                    {
                        arrIDs.Add(queryObj["ID"].ToString());
                    }
                }
            }
        }

        public static void CollectProps(string filter, ref StringDictionary propColl)
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(filter))
            {
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    foreach (PropertyData property in queryObj.Properties)
                    {
                        propColl.Add(property.Name, Convert.ToString(property.Value));
                    }
                }
            }
        }

        public static void ParseList(string SLProduct, string SLService, List<string> arrList)
        {
            foreach (string item in arrList)
            {
                GetResult(SLProduct, SLService, item);
                Console.WriteLine(line3);
                if (!ShowAll) {Console.WriteLine();}
            }
        }

        public static void DetectSubscription(StringDictionary objSvc)
        {
            string subType = objSvc["SubscriptionType"];
            if (subType == "120")
            {
                return;
            }
            string SubMsgType;
            if (subType == "1")
            {
                SubMsgType = "Device based";
            }
            else
            {
                SubMsgType = "User based";
            }
            string subState = objSvc["SubscriptionStatus"];
            string SubMsgStatus;
            switch (subState)
            {
                case "120":
                    SubMsgStatus = "Expired";
                    break;
                case "100":
                    SubMsgStatus = "Disabled";
                    break;
                case "1":
                    SubMsgStatus = "Active";
                    break;
                default:
                    SubMsgStatus = "Not active";
                    break;
            }
            string SubMsgExpiry = objSvc["SubscriptionExpiry"];
            if (SubMsgExpiry.Contains("unspecified"))
            {
                SubMsgExpiry = "Unknown";
            }
            string SubMsgEdition = objSvc["SubscriptionEdition"];
            if (SubMsgEdition.Contains("UNKNOWN"))
            {
                SubMsgEdition = "Unknown";
            }
            Console.WriteLine("\r\nSubscription information:");
            Console.WriteLine("    Type   : " + SubMsgType);
            Console.WriteLine("    Status : " + SubMsgStatus);
            Console.WriteLine("    Edition: " + SubMsgEdition);
            Console.WriteLine("    Expiry : " + SubMsgExpiry);
        }

        public static void DetectAdbaClient(StringDictionary objPrd)
        {
            DetectActType(objPrd);
            Console.WriteLine("\r\nAD Activation client information:");
            Console.WriteLine("    Object Name: " + objPrd["ADActivationObjectName"]);
            Console.WriteLine("    Domain Name: " + objPrd["ADActivationObjectDN"]);
            Console.WriteLine("    CSVLK Extended PID: " + objPrd["ADActivationCsvlkPid"]);
            Console.WriteLine("    CSVLK Activation ID: " + objPrd["ADActivationCsvlkSkuId"]);
        }

        public static void DetectAvmClient(StringDictionary objPrd)
        {
            Console.WriteLine("\r\nAutomatic VM Activation client information:");
            if (!String.IsNullOrEmpty(objPrd["IAID"]))
            {
                Console.WriteLine("    Guest IAID: " + objPrd["IAID"]);
            }
            else
            {
                Console.WriteLine("    Guest IAID: Not Available");
            }
            if (!String.IsNullOrEmpty(objPrd["AutomaticVMActivationHostMachineName"]))
            {
                Console.WriteLine("    Host machine name: " + objPrd["AutomaticVMActivationHostMachineName"]);
            }
            else
            {
                Console.WriteLine("    Host machine name: Not Available");
            }
            if (!String.IsNullOrEmpty(objPrd["AutomaticVMActivationHostDigitalPid2"]))
            {
                Console.WriteLine("    Host Digital PID2: " + objPrd["AutomaticVMActivationHostDigitalPid2"]);
            }
            else
            {
                Console.WriteLine("    Host Digital PID2: Not Available");
            }
            string avmTime = objPrd["AutomaticVMActivationLastActivationTime"];
            if ((avmTime).Substring(0,4) != "1601")
            {
                DateTime LAT = DateTime.Parse(ManagementDateTimeConverter.ToDateTime(avmTime).ToString(), null, (System.Globalization.DateTimeStyles)48);
                Console.WriteLine("    Activation time: " + LAT.ToString("yyyy-MM-dd hh:mm:ss tt") + " UTC");
            }
            else
            {
                Console.WriteLine("    Activation time: Not Available");
            }
        }

        public static void DetectKmsServer(StringDictionary objPrd, StringDictionary objSvc, bool isOld)
        {
            string IsKMS = "0";
            IsKMS = objPrd["IsKeyManagementServiceMachine"];
            if (IsKMS == "0") {return;}

            string kmsListening;
            bool kmsPublishing;
            bool kmsPriority;
            string strPublishing;
            string strPriority;
            if (isOld)
            {
                string regListening = GetRegString(SLKeyPath, "KeyManagementServiceListeningPort");
                uint regPublishing = GetRegDword(SLKeyPath, "DisableDnsPublishing", 0);
                uint regPriority   = GetRegDword(SLKeyPath, "EnableKmsLowPriority", 0);
                kmsListening = String.IsNullOrEmpty(regListening) == true ? "1688" : regListening;
                kmsPublishing = regPublishing == 0;
                kmsPriority = regPriority != 0;
            }
            else
            {
                kmsListening = objSvc["KeyManagementServiceListeningPort"];
                kmsPublishing = Convert.ToBoolean(objSvc["KeyManagementServiceDnsPublishing"]);
                kmsPriority = Convert.ToBoolean(objSvc["KeyManagementServiceLowPriority"]);
            }

            if (kmsListening == "0")
            {
                kmsListening = "1688";
            }
            if (kmsPublishing)
            {
                strPublishing = "Enabled";
            }
            else
            {
                strPublishing = "Disabled";
            }
            if (kmsPriority)
            {
                strPriority = "Low";
            }
            else
            {
                strPriority = "Normal";
            }

            string KMSRequests = "-1";
            KMSRequests = objPrd["KeyManagementServiceTotalRequests"];

            Console.WriteLine("\r\nKey Management Service host information:");
            Console.WriteLine("    Current count: " + objPrd["KeyManagementServiceCurrentCount"]);
            Console.WriteLine("    Listening on Port: " + kmsListening);
            Console.WriteLine("    DNS publishing: " + strPublishing);
            Console.WriteLine("    KMS priority: " + strPriority);
            if (KMSRequests == "-1" || KMSRequests == (uint.MaxValue).ToString())
            {
                return;
            }

            string reqFFF, reqUnl, reqLic, reqOOB, reqOOT, reqOOG, reqNTF = string.Empty;
            reqFFF = objPrd["KeyManagementServiceFailedRequests"];
            reqUnl = objPrd["KeyManagementServiceUnlicensedRequests"];
            reqLic = objPrd["KeyManagementServiceLicensedRequests"];
            reqOOB = objPrd["KeyManagementServiceOOBGraceRequests"];
            reqOOT = objPrd["KeyManagementServiceOOTGraceRequests"];
            reqOOG = objPrd["KeyManagementServiceNonGenuineGraceRequests"];
            reqNTF = objPrd["KeyManagementServiceNotificationRequests"];

            Console.WriteLine("\r\nKey Management Service cumulative requests received from clients:");
            Console.WriteLine("    Total: " + KMSRequests);
            Console.WriteLine("    Failed: " + reqFFF);
            Console.WriteLine("    Unlicensed: " + reqUnl);
            Console.WriteLine("    Licensed: " + reqLic);
            Console.WriteLine("    Initial grace period: " + reqOOB);
            Console.WriteLine("    Expired or Hardware out of tolerance: " + reqOOT);
            Console.WriteLine("    Non-genuine grace period: " + reqOOG);
            if (!String.IsNullOrEmpty(reqNTF)) {Console.WriteLine("    Notification: " + reqNTF);}
        }

        public static void DetectActType(StringDictionary objPrd)
        {
            uint VLType = Convert.ToUInt32(objPrd["VLActivationTypeEnabled"]);
            Console.WriteLine("Configured Activation Type: " + VLActTypes[VLType]);
        }

        public static void DetectKmsClient(StringDictionary objPrd, StringDictionary objSvc, bool isNT6, bool isNT8, bool isNT9, uint lState)
        {
            if (isNT8) {DetectActType(objPrd);}
            Console.WriteLine();
            if (lState != 1)
            {
                Console.WriteLine("Please activate the product in order to update KMS client information values.");
                return;
            }

            string DiscIP = string.Empty;
            if (isNT9)
            {
                DiscIP = objPrd["DiscoveredKeyManagementServiceMachineIpAddress"];
                if (!String.IsNullOrEmpty(DiscIP))
                {
                    DiscIP = "not available";
                }
            }

            string kmsName, kmsPort, DiscName, DiscPort, intervalAct, intervalRen, kmsPID;
            string kmsDomain = string.Empty, kmsCaching = string.Empty;
            intervalAct = objPrd["VLActivationInterval"];
            intervalRen = objPrd["VLRenewalInterval"];
            kmsPID = objPrd["KeyManagementServiceProductKeyID"];
            kmsName = objPrd["KeyManagementServiceName"];
            if (isNT6)
            {
                string regPort = GetRegString(SLKeyPath, "KeyManagementServicePort");
                string regDscP = GetRegString(NSKeyPath, "DiscoveredKeyManagementServicePort");
                kmsPort = String.IsNullOrEmpty(regPort) == true ? "1688" : regPort;
                DiscPort = String.IsNullOrEmpty(regDscP) == true ? "1688" : regDscP;
                DiscName = GetRegString(NSKeyPath, "DiscoveredKeyManagementServiceName");
                kmsDomain = GetRegString(SLKeyPath, "KeyManagementServiceLookupDomain");
            }
            else
            {
                kmsPort = objPrd["KeyManagementServicePort"];
                DiscPort = objPrd["DiscoveredKeyManagementServiceMachinePort"];
                DiscName = objPrd["DiscoveredKeyManagementServiceMachineName"];
                if (isNT8)
                {
                    kmsDomain = objPrd["KeyManagementServiceLookupDomain"];
                }
                else
                {
                    if (!(objPrd["Name"]).Contains("Office"))
                    {
                        kmsDomain = GetRegString(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform", "KeyManagementServiceLookupDomain");
                    }
                }
                if (Convert.ToBoolean(objSvc["KeyManagementServiceHostCaching"]) == true)
                {
                    kmsCaching = "Enabled";
                }
                else
                {
                    kmsCaching = "Disabled";
                }
            }

            string KmsReg;
            if (String.IsNullOrEmpty(kmsName))
            {
                KmsReg = string.Empty;
            }
            else
            {
                if (kmsPort == "0") {kmsPort = "1688";}
                KmsReg = String.Format("Registered KMS machine name: {0}:{1}", kmsName, kmsPort);
            }

            string KmsDns;
            if (String.IsNullOrEmpty(DiscName))
            {
                KmsDns = "DNS auto-discovery: KMS name not available";
                if (isNT6 && !Elevated) {KmsDns = "DNS auto-discovery: Run as administrator to retrieve info";}
            }
            else
            {
                if (DiscPort == "0") {DiscPort = "1688";}
                KmsDns = String.Format("KMS machine name from DNS: {0}:{1}", DiscName, DiscPort);
            }

            Console.WriteLine("Key Management Service client information:");
            Console.WriteLine("    Client Machine ID (CMID): " + objSvc["ClientMachineID"]);
            if (String.IsNullOrEmpty(KmsReg))
            {
                Console.WriteLine("    " + KmsDns);
                Console.WriteLine("    Registered KMS machine name: KMS name not available");
            }
            else
            {
                Console.WriteLine("    " + KmsReg);
            }
            if (!String.IsNullOrEmpty(DiscIP)) {Console.WriteLine("    KMS machine IP address: " + DiscIP);}
            Console.WriteLine("    KMS machine extended PID: " + kmsPID);
            Console.WriteLine("    Activation interval: " + intervalAct + " minutes");
            Console.WriteLine("    Renewal interval: " + intervalRen + " minutes");
            if (!String.IsNullOrEmpty(kmsCaching)) {Console.WriteLine("    KMS host caching: " + kmsCaching);}
            if (!String.IsNullOrEmpty(kmsDomain)) {Console.WriteLine("    KMS SRV record lookup domain: " + kmsDomain);}
        }

        public static void GetResult(string strSLP, string strSLS, string strID)
        {
            string fltr = String.Format("SELECT * FROM {0} WHERE ID='{1}'", strSLP, strID);
            StringDictionary objPrd = new StringDictionary();
            try
            {
                CollectProps(fltr, ref objPrd);
            }
            catch
            {
                return;
            }
            if (!objPrd.ContainsKey("ID"))
            {
                return;
            }

            string licApp = objPrd["ApplicationID"];
            string licID = objPrd["ID"];
            string licName = objPrd["Name"];
            string licDesc = objPrd["Description"];
            string licPPK = objPrd["PartialProductKey"];
            uint licState = Convert.ToUInt32(objPrd["LicenseStatus"]);

            int add_on = licName.IndexOf("add-on for", StringComparison.OrdinalIgnoreCase);
            if (add_on != -1)
            {
                licName = licName.Substring(0, add_on + 7);
            }

            bool isPPK = String.IsNullOrEmpty(licPPK) == false;

            if (licState == 0 && !isPPK)
            {
                if (ShowAll) {Console.WriteLine();}
                Console.WriteLine("Name: " + licName);
                Console.WriteLine("Description: " + licDesc);
                Console.WriteLine("Activation ID: " + licID);
                Console.WriteLine("License Status: Unlicensed");
                return;
            }

            bool winID = (licApp.Equals(winApp));
            bool Vista = (winID && NT6 && !NT7);
            bool NT5 = (strSLP.Equals(wslp) && winbuild < 6001);
            bool win8 = (strSLP.Equals(wslp) && NT8);
            bool winPR = (winID && (objPrd.ContainsKey("LicenseIsAddon") == false || objPrd["LicenseIsAddon"] == "False"));
            string reapp = winID == true ? "Windows" : "App";
            string prmnt = winPR == true ? "machine" : "product";

            string licCHN = objPrd["ProductKeyChannel"];
            string licEPID = objPrd["ProductKeyID"];
            string licPID2 = objPrd["ProductKeyID2"];
            string licIID = objPrd["OfflineInstallationId"];
            uint gprMnt = Convert.ToUInt32(objPrd["GracePeriodRemaining"]);
            uint gprDay = Convert.ToUInt32(Math.Round(Convert.ToDouble(gprMnt / 1440)));

            string LicenseInf = string.Empty, LicenseMsg = string.Empty, ExpireMsg = string.Empty, actTag = string.Empty;
            bool cKmsServer = false, cKmsClient = false, cAvmClient = false;

            if (licDesc.Contains("VOLUME_KMSCLIENT")) {cKmsClient = true; actTag = "Volume";}
            if (licDesc.Contains("TIMEBASED_")) {actTag = "Timebased";}
            if (licDesc.Contains("VIRTUAL_MACHINE_ACTIVATION")) {cAvmClient = true; actTag = "Automatic VM";}
            if (!cKmsClient && licDesc.Contains("VOLUME_KMS")) {cKmsServer = true;}

            string xpr = "";
            bool inGrace = false;
            if (gprMnt > 0)
            {
                xpr = (DateTime.Now.AddMinutes(gprMnt)).ToString("yyyy-MM-dd hh:mm:ss tt");
                inGrace = true;
            }

            LicenseMsg = "Time remaining: " + gprMnt + " minute(s) (" + gprDay + " day(s))";
            if (licState == 0)
            {
                LicenseInf = "Unlicensed";
                LicenseMsg = "";
            }
            if (licState == 1)
            {
                LicenseInf = "Licensed";
                if (gprMnt == 0)
                {
                    LicenseMsg = "";
                    ExpireMsg = "The " + prmnt + " is permanently activated.";
                }
                else
                {
                    LicenseMsg = actTag + " activation expiration: " + gprMnt + " minute(s) (" + gprDay + " day(s))";
                    if (inGrace) {ExpireMsg = actTag + " activation will expire " + xpr;}
                }
            }
            if (licState == 2)
            {
                LicenseInf = "Initial grace period";
                if (inGrace) {ExpireMsg = LicenseInf + " ends " + xpr;}
            }
            if (licState == 3)
            {
                LicenseInf = "Additional grace period";
                if (inGrace) {ExpireMsg = LicenseInf + " ends " + xpr;}
            }
            if (licState == 4)
            {
                LicenseInf = "Non-genuine grace period";
                if (inGrace) {ExpireMsg = LicenseInf + " ends " + xpr;}
            }
            if (licState == 5 && !NT5)
            {
                uint LicReason = Convert.ToUInt32(objPrd["LicenseStatusReason"]);
                string LicenseReason = "0x" + LicReason.ToString("X8");
                LicenseInf = "Notification";
                LicenseMsg = "Notification Reason: " + LicenseReason;
                if (LicenseReason == "0xC004F00F") {if (cKmsClient) {LicenseMsg = LicenseMsg + " (KMS license expired).";} else {LicenseMsg = LicenseMsg + " (hardware out of tolerance).";}}
                if (LicenseReason == "0xC004F200") {LicenseMsg = LicenseMsg + " (non-genuine).";}
                if (LicenseReason == "0xC004F009" || LicenseReason == "0xC004F064") {LicenseMsg = LicenseMsg + " (grace time expired).";}
            }
            if (licState > 5 || (licState > 4 && NT5))
            {
                LicenseInf = "Unknown";
                LicenseMsg = "";
            }
            if (licState == 6 && !Vista && !NT5)
            {
                LicenseInf = "Extended grace period";
                if (inGrace) {ExpireMsg = LicenseInf + " ends " + xpr;}
            }

            if (winPR && !NT9 && isPPK)
            {
                byte[] dp4 = (byte[])Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DigitalProductId4", null);
                if (dp4 != null)
                {
                    licCHN = (System.Text.Encoding.Unicode.GetString(dp4, 1016, 128)).Trim('\0');
                }
            }

            bool chkWRC = (winPR && NT7 && ShowDlv && !objPrd.ContainsKey("RemainingAppReArmCount"));
            bool chkSub = (winPR && isSub);
            bool chkSLS = isPPK && (cKmsClient || cKmsServer || chkSub || chkWRC);

            StringDictionary objSvc = new StringDictionary();
            if (chkSLS)
            {
                try
                {
                    CollectProps("SELECT * FROM " + strSLS, ref objSvc);
                    if (!objPrd.ContainsKey("IsKeyManagementServiceMachine"))
                    {
                        foreach(DictionaryEntry kvp in objSvc)
                        {
                            objPrd.Add((string)kvp.Key, (string)kvp.Value);
                        }
                    }
                }
                catch
                {
                }
            }

            if (ShowAll) {Console.WriteLine();}
            Console.WriteLine("Name: " + licName);
            Console.WriteLine("Description: " + licDesc);
            Console.WriteLine("Activation ID: " + licID);
            if (!String.IsNullOrEmpty(licEPID)) {Console.WriteLine("Extended PID: " + licEPID);}
            if (!String.IsNullOrEmpty(licPID2) && ShowDlv) {Console.WriteLine("Product ID: " + licPID2);}
            if (!String.IsNullOrEmpty(licIID) && ShowIID) {Console.WriteLine("Installation ID: " + licIID);}
            if (!String.IsNullOrEmpty(licCHN)) {Console.WriteLine("Product Key Channel: " + licCHN);}
            if (isPPK) {Console.WriteLine("Partial Product Key: " + licPPK);}
            Console.WriteLine("License Status: " + LicenseInf);
            if (!String.IsNullOrEmpty(LicenseMsg)) {Console.WriteLine(LicenseMsg);}
            string evlTime = objPrd["EvaluationEndDate"];
            if (licState != 0 && (evlTime).Substring(0,4) != "1601")
            {
                DateTime EED = DateTime.Parse(ManagementDateTimeConverter.ToDateTime(evlTime).ToString(), null, (System.Globalization.DateTimeStyles)48);
                Console.WriteLine("Evaluation End Date: " + EED.ToString("yyyy-MM-dd hh:mm:ss tt") + " UTC");
            }

            if (ShowDlv && isPPK)
            {
                string rearmApp = "-1", rearmSku = "-1", rearmWin = "-1";
                if (win8 && NT9)
                {
                    rearmApp = objPrd["RemainingAppReArmCount"];
                    rearmSku = objPrd["RemainingSkuReArmCount"];
                }
                else if (winID && NT7)
                {
                    rearmWin = objSvc["RemainingWindowsReArmCount"];
                }
                if (rearmWin != "-1")
                {
                    Console.WriteLine("Remaining Windows rearm count: " + rearmWin);
                }
                if (rearmSku != "-1" && rearmSku != (uint.MaxValue).ToString())
                {
                    Console.WriteLine("Remaining "+reapp+" rearm count: " + rearmApp);
                    Console.WriteLine("Remaining SKU rearm count: " + rearmSku);
                }
                string dtfTime = objPrd["TrustedTime"];
                if (!String.IsNullOrEmpty(dtfTime) && licState != 0)
                {
                    DateTime TTD = DateTime.Parse(ManagementDateTimeConverter.ToDateTime(dtfTime).ToString(), null, (System.Globalization.DateTimeStyles)32);
                    Console.WriteLine("Trusted time: " + TTD.ToString("yyyy-MM-dd hh:mm:ss tt"));
                }
            }

            if (!isPPK)
            {
                return;
            }
            if (win8 && objPrd["VLActivationType"] == "1")
            {
                DetectAdbaClient(objPrd);
                cKmsClient = false;
            }
            if (winID && cAvmClient)
            {
                DetectAvmClient(objPrd);
            }
            if (!chkSLS)
            {
                if (!String.IsNullOrEmpty(ExpireMsg)) {Console.WriteLine("\r\n    " + ExpireMsg);}
                return;
            }
            if (cKmsClient)
            {
                DetectKmsClient(objPrd, objSvc, Vista, win8, (strSLS.Equals(wsls) && NT9), licState);
            }
            if (cKmsServer)
            {
                if (!String.IsNullOrEmpty(ExpireMsg)) {Console.WriteLine("\r\n    " + ExpireMsg);}
                DetectKmsServer(objPrd, objSvc, (Vista || NT5));
            }
            else
            {
                if (!String.IsNullOrEmpty(ExpireMsg)) {Console.WriteLine("\r\n    " + ExpireMsg);}
            }
            if (chkSub)
            {
                DetectSubscription(objSvc);
            }
        }

        public static uint GetRegDword(string strKey, string strName, uint dwDefault)
        {
            try
            {
                return (uint)Registry.GetValue(strKey, strName, dwDefault);
            }
            catch
            {
                return dwDefault;
            }
        }

        public static string GetRegString(string strKey, string strName)
        {
            try
            {
                return (string)Registry.GetValue(strKey, strName, null);
            }
            catch
            {
                return null;
            }
        }
#endregion
    }

    internal static class Services
    {
        public static void DoStart(string serviceName)
        {
            using (ServiceController sc = new ServiceController(serviceName))
            {
                if (sc.Status == ServiceControllerStatus.Stopped)
                {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, new TimeSpan(0, 0, 20));
                }
            }
        }

        public static bool IsInstalled(string serviceName)
        {
            using (ServiceController sc = new ServiceController(serviceName))
            {
                try
                {
                    return (sc.ServiceName != null);
                }
                catch
                {
                    return false;
                }
            }
        }
    }
}

#region clic
namespace CLIC
{
    internal static class NativeMethods
    {
        [DllImport("Clipc.dll", PreserveSig = true)]
        public static extern int ClipGetSubscriptionStatus(out IntPtr ppStatus);

        [DllImport("slc.dll", PreserveSig = true)]
        public static extern int SLIsWindowsGenuineLocal(out uint pGenuineState);

        [DllImport("slc.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
        public static extern int SLGetWindowsInformationDWORD(string pwszValueName, out uint pdwValue);

        [DllImport("slc.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
        public static extern int SLGetWindowsInformation(string pwszValueName, IntPtr peDataType, out uint pcbValue, out IntPtr ppbValue);
    }

    [ComImport, Guid("F2DCB80D-0670-44BC-9002-CD18688730AF"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IEditionUpgradeManager
    {
        void unused1();
        void unused2();
        void unused3();
        void unused4();
        [PreserveSig] int AcquireModernLicenseForWindows(int bAsync, out int lmReturnCode);
    }

    public static class Program
    {
        public static string[] SL_GENUINE_STATE = new string[]
        {
            "SL_GEN_STATE_IS_GENUINE",
            "SL_GEN_STATE_INVALID_LICENSE",
            "SL_GEN_STATE_TAMPERED",
            "SL_GEN_STATE_OFFLINE",
            "SL_GEN_STATE_LAST"
        };

        public static string BoolToWStr(uint bVal)
        {
            if (bVal == 0) { return "FALSE"; } else { return "TRUE"; }
        }

        public static void PrintStateData()
        {
            IntPtr pwszStateData;
            uint cbSize;
            try
            {
                if (NativeMethods.SLGetWindowsInformation("Security-SPP-Action-StateData", IntPtr.Zero, out cbSize, out pwszStateData) != 0)
                {
                    return;
                }
            }
            catch
            {
                return;
            }

            Console.WriteLine("    " + Marshal.PtrToStringUni(pwszStateData).Replace(";", "\n    "));
            Marshal.FreeHGlobal(pwszStateData);
            return;
        }

        public static void PrintLastActivationHResult()
        {
            IntPtr pdwLastHResult;
            uint cbSize;
            try
            {
                if (NativeMethods.SLGetWindowsInformation("Security-SPP-LastWindowsActivationHResult", IntPtr.Zero, out cbSize, out pdwLastHResult) != 0)
                {
                    return;
                }
            }
            catch
            {
                return;
            }

            Console.WriteLine("    LastActivationHResult=0x{0:x8}", Marshal.ReadInt32(pdwLastHResult));
            Marshal.FreeHGlobal(pdwLastHResult);
            return;
        }

        public static void PrintLastActivationTime()
        {
            IntPtr pqwLastTime;
            uint cbSize;
            try
            {
                if (NativeMethods.SLGetWindowsInformation("Security-SPP-LastWindowsActivationTime", IntPtr.Zero, out cbSize, out pqwLastTime) != 0)
                {
                    return;
                }
            }
            catch
            {
                return;
            }

            long actTime = Marshal.ReadInt64(pqwLastTime);
            if (actTime != 0)
            {
                Console.WriteLine("    LastActivationTime={0}", DateTime.FromFileTimeUtc(actTime).ToString("yyyy/MM/dd:HH:mm:ss"));
            }
            Marshal.FreeHGlobal(pqwLastTime);
            return;
        }

        public static void PrintIsWindowsGenuine()
        {
            uint pdwGenuineState;
            try
            {
                if (NativeMethods.SLIsWindowsGenuineLocal(out pdwGenuineState) != 0)
                {
                    return;
                }
            }
            catch
            {
                return;
            }

            if (pdwGenuineState < 5)
            {
                Console.WriteLine("    IsWindowsGenuine={0}", SL_GENUINE_STATE[pdwGenuineState]);
            }
            else
            {
                Console.WriteLine("    IsWindowsGenuine={0}", pdwGenuineState);
            }
            return;
        }

        public static void PrintSubscriptionStatus()
        {
            IntPtr pStatus = Marshal.AllocHGlobal(12);
            try
            {
                if (NativeMethods.ClipGetSubscriptionStatus(out pStatus) != 0)
                {
                    return;
                }
            }
            catch
            {
                return;
            }

            int dwEnabled = Marshal.ReadInt32(pStatus);
            Console.WriteLine("    SubscriptionEnabled={0}", BoolToWStr((uint)dwEnabled));
            if (dwEnabled >= 1)
            {
                Console.WriteLine("    SubscriptionSku={0}", Marshal.ReadInt32(pStatus, 4));
                Console.WriteLine("    SubscriptionState={0}", Marshal.ReadInt32(pStatus, 8));
            }
            Marshal.FreeHGlobal(pStatus);
            return;
        }

        public static void PrintDigitalLicenseStatus()
        {
            Type m_IEditionUpgradeManager;
            Object ComObj;
            try
            {
                m_IEditionUpgradeManager = typeof(CLIC.IEditionUpgradeManager);
                ComObj = Activator.CreateInstance(Type.GetTypeFromProgID("EditionUpgradeManagerObj.EditionUpgradeManager"));
            }
            catch
            {
                return;
            }

            Object[] parameters = new Object[] { 1, null };
            Object result = m_IEditionUpgradeManager.GetMethod("AcquireModernLicenseForWindows").Invoke(ComObj, parameters);
            if (Convert.ToInt32(result) != 0)
            {
                return;
            }

            int dwReturnCode = -1;
            dwReturnCode = (int)parameters[1];
            int bDigitalLicense = (dwReturnCode >= 0 && dwReturnCode != 1) ? 1 : 0;
            Console.WriteLine("    IsDigitalLicense={0}", BoolToWStr((uint)bDigitalLicense));
            return;
        }

        public static void ClicRun(bool DllDigital, bool DllSubscription)
        {
            Console.WriteLine("Client Licensing Check:");

            try
            {
                PrintStateData();

                PrintLastActivationHResult();

                PrintLastActivationTime();

                PrintIsWindowsGenuine();

                if (DllDigital)
                    PrintDigitalLicenseStatus();

                if (DllSubscription)
                    PrintSubscriptionStatus();
            }
            catch
            {
            }
        }
    }
}
#endregion
