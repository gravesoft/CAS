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
using System.Reflection.Emit;
using System.Diagnostics;

namespace CAS
{
    public static class Program
    {
        public static string SysPath = File.Exists(Environment.GetEnvironmentVariable("SystemRoot") + @"\Sysnative\cmd.exe") ? (Environment.GetEnvironmentVariable("SystemRoot") + @"\Sysnative") : Environment.SystemDirectory;
        public static int winbuild = FileVersionInfo.GetVersionInfo(SysPath + @"\kernel32.dll").FileBuildPart;

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
        public static bool SLApp = true;
        public static bool DllDigital = (winbuild >= 14393 && File.Exists(SysPath + @"\EditionUpgradeManagerObj.dll"));
        public static bool DllSubscription = (winbuild >= 14393 && File.Exists(SysPath + @"\Clipc.dll"));

        public static string line2 = "============================================================";
        public static string line3 = "____________________________________________________________";

        public static Type Win32;
        public static IntPtr hSLC;

        public static void DefinePInvoke(string func, string lib, Type ret, Type[] parameters, ref TypeBuilder tb)
        {
            tb.DefinePInvokeMethod(func, lib, MethodAttributes.Public | MethodAttributes.Static, CallingConventions.Standard, ret, parameters, CallingConvention.Winapi, CharSet.Unicode).SetImplementationFlags(MethodImplAttributes.PreserveSig);
        }

        public static void InitializePInvoke(string LaDll, bool bOffice, out Type tWin32)
        {
            string LaName = Path.GetFileNameWithoutExtension(LaDll);
            SLApp = NT7 || bOffice || (LaName.Equals("sppc") && FileVersionInfo.GetVersionInfo(SysPath + @"\sppc.dll").FilePrivatePart >= 16501);
            tWin32 = null;

            ModuleBuilder Module = AppDomain.CurrentDomain.DefineDynamicAssembly(new AssemblyName(LaName+"_Assembly"), AssemblyBuilderAccess.Run).DefineDynamicModule(LaName+"_Module", false);
            TypeBuilder Class = Module.DefineType(LaName+"_Methods", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed | TypeAttributes.BeforeFieldInit, typeof(Object), 0);

            DefinePInvoke("SLClose", LaDll, typeof(Int32), new Type[] {typeof(IntPtr)}, ref Class);
            DefinePInvoke("SLOpen", LaDll, typeof(Int32), new Type[] {typeof(IntPtr).MakeByRefType()}, ref Class);
            DefinePInvoke("SLGenerateOfflineInstallationId", LaDll, typeof(Int32), new Type[] {typeof(IntPtr), typeof(Guid).MakeByRefType(), typeof(IntPtr).MakeByRefType()}, ref Class);
            DefinePInvoke("SLGetSLIDList", LaDll, typeof(Int32), new Type[] {typeof(IntPtr), typeof(UInt32), typeof(Guid).MakeByRefType(), typeof(UInt32), typeof(UInt32).MakeByRefType(), typeof(IntPtr).MakeByRefType()}, ref Class);
            DefinePInvoke("SLGetLicensingStatusInformation", LaDll, typeof(Int32), new Type[] {typeof(IntPtr), typeof(Guid).MakeByRefType(), typeof(Guid).MakeByRefType(), typeof(IntPtr), typeof(UInt32).MakeByRefType(), typeof(IntPtr).MakeByRefType()}, ref Class);
            DefinePInvoke("SLGetPKeyInformation", LaDll, typeof(Int32), new Type[] {typeof(IntPtr), typeof(Guid).MakeByRefType(), typeof(String), typeof(UInt32).MakeByRefType(), typeof(UInt32).MakeByRefType(), typeof(IntPtr).MakeByRefType()}, ref Class);
            DefinePInvoke("SLGetProductSkuInformation", LaDll, typeof(Int32), new Type[] {typeof(IntPtr), typeof(Guid).MakeByRefType(), typeof(String), typeof(UInt32).MakeByRefType(), typeof(UInt32).MakeByRefType(), typeof(IntPtr).MakeByRefType()}, ref Class);
            DefinePInvoke("SLGetServiceInformation", LaDll, typeof(Int32), new Type[] {typeof(IntPtr), typeof(String), typeof(UInt32).MakeByRefType(), typeof(UInt32).MakeByRefType(), typeof(IntPtr).MakeByRefType()}, ref Class);
            if (SLApp)
            {
                DefinePInvoke("SLGetApplicationInformation", LaDll, typeof(Int32), new Type[] {typeof(IntPtr), typeof(Guid).MakeByRefType(), typeof(String), typeof(UInt32).MakeByRefType(), typeof(UInt32).MakeByRefType(), typeof(IntPtr).MakeByRefType()}, ref Class);
            }
            if (bOffice)
            {
                tWin32 = Class.CreateType();
                return;
            }
            if (NT6)
            {
                DefinePInvoke("SLGetWindowsInformation", "slc.dll", typeof(Int32), new Type[] {typeof(String), typeof(UInt32).MakeByRefType(), typeof(UInt32).MakeByRefType(), typeof(IntPtr).MakeByRefType()}, ref Class);
                DefinePInvoke("SLGetWindowsInformationDWORD", "slc.dll", typeof(Int32), new Type[] {typeof(String), typeof(UInt32).MakeByRefType()}, ref Class);
                DefinePInvoke("SLIsGenuineLocal", "slwga.dll", typeof(Int32), new Type[] {typeof(Guid).MakeByRefType(), typeof(UInt32).MakeByRefType(), typeof(IntPtr)}, ref Class);
            }
            if (NT7)
            {
                DefinePInvoke("SLIsWindowsGenuineLocal", "slc.dll", typeof(Int32), new Type[] {typeof(UInt32).MakeByRefType()}, ref Class);
            }
            if (DllSubscription)
            {
                DefinePInvoke("ClipGetSubscriptionStatus", "Clipc.dll", typeof(Int32), new Type[] {typeof(IntPtr).MakeByRefType()}, ref Class);
            }

            tWin32 = Class.CreateType();
            return;
        }

        public static void OpenSL(ref IntPtr hSLC)
        {
            Object[] parameters = new Object[] { null };
            Win32.GetMethod("SLOpen").Invoke(null, parameters);
            hSLC = (IntPtr)parameters[0];
        }

        public static void CloseSL(IntPtr hSLC)
        {
            Win32.GetMethod("SLClose").Invoke(null, new Object[] { hSLC });
        }

        public static string wslp = "SoftwareLicensingProduct";
        // public static string wsls = "SoftwareLicensingService";
        public static string oslp = "OfficeSoftwareProtectionProduct";
        // public static string osls = "OfficeSoftwareProtectionService";
        public static string winApp = "55c92734-d682-4d71-983e-d6ec3f16059f";
        public static string o14App = "59a52881-a989-479d-af46-f275c6370663";
        public static string o15App = "0ff1ce15-a989-479d-af46-f275c6370663";
        public static string[] VLActTypes = new string[] {"All", "AD", "KMS", "Token"};
        public static string OPKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform";
        public static string SPKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform";
        public static string SLKeyPath = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SL";
        public static string NSKeyPath = @"HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SL";
        public static string[] propPrd = new string[] {"Name", "Description", "TrustedTime", "VLActivationType"};
        public static string[] propPkey = new string[] {"PartialProductKey", "Channel", "DigitalPID", "DigitalPID2"};
        public static string[] propKMSServer = new string[] {"KeyManagementServiceCurrentCount", "KeyManagementServiceTotalRequests", "KeyManagementServiceFailedRequests", "KeyManagementServiceUnlicensedRequests", "KeyManagementServiceLicensedRequests", "KeyManagementServiceOOBGraceRequests", "KeyManagementServiceOOTGraceRequests", "KeyManagementServiceNonGenuineGraceRequests", "KeyManagementServiceNotificationRequests"};
        public static string[] propKMSClient = new string[] {"CustomerPID", "KeyManagementServiceName", "KeyManagementServicePort", "DiscoveredKeyManagementServiceName", "DiscoveredKeyManagementServicePort", "DiscoveredKeyManagementServiceIpAddress", "VLActivationInterval", "VLRenewalInterval", "KeyManagementServiceLookupDomain"};
        public static string[] propKMSVista = new string[] {"CustomerPID", "KeyManagementServiceName", "VLActivationInterval", "VLRenewalInterval"};
        public static string[] propADBA = new string[] {"ADActivationObjectName", "ADActivationObjectDN", "ADActivationCsvlkPID", "ADActivationCsvlkSkuID"};
        public static string[] propAVMA = new string[] {"InheritedActivationId", "InheritedActivationHostMachineName", "InheritedActivationHostDigitalPid2", "InheritedActivationActivationTime"};
        public static bool isSub = false;
        public static Hashtable primary = new Hashtable();
        public static string[] SL_GENUINE_STATE = new string[]
        {
            "SL_GEN_STATE_IS_GENUINE",
            "SL_GEN_STATE_INVALID_LICENSE",
            "SL_GEN_STATE_TAMPERED",
            "SL_GEN_STATE_OFFLINE",
            "SL_GEN_STATE_LAST"
        };
        public static string[] SLLICENSINGSTATUS = new string[]
        {
            "SL_LICENSING_STATUS_UNLICENSED",
            "SL_LICENSING_STATUS_LICENSED",
            "SL_LICENSING_STATUS_IN_GRACE_PERIOD",
            "SL_LICENSING_STATUS_NOTIFICATION",
            "SL_LICENSING_STATUS_LAST"
        };

        internal static bool checkSubscription()
        {
            bool testSub = false;
            using (StreamReader rdr = new StreamReader(SysPath + @"\wbem\sppwmi.mof", System.Text.Encoding.Unicode))
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

        internal static void echoWindows()
        {
            Console.WriteLine(line2);
            Console.WriteLine("===                   Windows Status                     ===");
            Console.WriteLine(line2);
            if (!ShowAll) {Console.WriteLine();}
        }

        internal static void echoOffice()
        {
            if (!ShowHeader) {return;}
            if (ShowAll) {Console.WriteLine();}
            Console.WriteLine(line2);
            Console.WriteLine("===                   Office Status                      ===");
            Console.WriteLine(line2);
            if (!ShowAll) {Console.WriteLine();}
            ShowHeader = false;
        }

        internal static void CheckOhook()
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

            List<Dictionary<string, string>> cW1nd0ws = new List<Dictionary<string, string>>(), c0ff1ce15 = new List<Dictionary<string, string>>(), c0ff1ce14 = new List<Dictionary<string, string>>(), ospp15 = new List<Dictionary<string, string>>(), ospp14 = new List<Dictionary<string, string>>();

            string offsvc = "osppsvc";
            string winsvc;
            if (NT7 || !NT6)
            {
                winsvc = "sppsvc";
            }
            else
            {
                winsvc = "slsvc";
            }

            bool WsppHook = Services.IsInstalled(winsvc);
            bool OsppHook = Services.IsInstalled(offsvc);

            string SLdll = "";
            if (File.Exists(SysPath + @"\sppc.dll"))
            {
                SLdll = "sppc.dll";
            }
            else if (File.Exists(SysPath + @"\slc.dll"))
            {
                SLdll = "slc.dll";
            }
            else
            {
                WsppHook = false;
            }

            string OLdll = "";
            if (OsppHook)
            {
                OLdll = GetRegString(OPKeyPath, "Path") + "osppc.dll";
                if (!File.Exists(OLdll)) {OsppHook = false;}
            }

            if (WsppHook)
            {
                if (NT6 && !NT7 && !Elevated)
                {
                    if (String.IsNullOrEmpty(Process.GetProcessesByName(winsvc)[0].ProcessName)) {WsppHook = false; Console.WriteLine("\r\nError: failed to start " + winsvc + " Service.\r\n");}
                }
                else
                {
                    try {Services.DoStart(winsvc);} catch {WsppHook = false; Console.WriteLine("\r\nError: failed to start " + winsvc + " Service.\r\n");}
                }
            }

            if (WsppHook)
            {
                InitializePInvoke(SLdll, false, out Win32);
                OpenSL(ref hSLC);

                SlGetInfoSLID(winApp, ref cW1nd0ws);
                SlGetInfoSLID(o15App, ref c0ff1ce15);
                SlGetInfoSLID(o14App, ref c0ff1ce14);
            }

            if (cW1nd0ws.Count > 0)
            {
                echoWindows();
                ParseList(wslp, winApp, cW1nd0ws);
            }
            else if (NT6)
            {
                echoWindows();
                Console.WriteLine("Error: product key not found.\r\n");
            }

            if (NT6 && !NT8)
            {
                if (ShowAll) {Console.WriteLine();}
                CLC.Program.ClcRun(primary);
                Console.WriteLine(line3);
                if (!ShowAll) {Console.WriteLine();}
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
                ParseList(wslp, o15App, c0ff1ce15);
            }

            if (c0ff1ce14.Count > 0)
            {
                echoOffice();
                ParseList(wslp, o14App, c0ff1ce14);
            }

            if (hSLC != IntPtr.Zero)
            {
                CloseSL(hSLC);
            }

            if (OsppHook)
            {
                try {Services.DoStart(offsvc);} catch {OsppHook = false; Console.WriteLine("\r\nError: failed to start " + offsvc + " Service.\r\n");}
            }

            if (OsppHook)
            {
                InitializePInvoke(OLdll, true, out Win32);
                OpenSL(ref hSLC);

                SlGetInfoSLID(o15App, ref ospp15);
                SlGetInfoSLID(o14App, ref ospp14);
            }

            if (ospp15.Count > 0)
            {
                echoOffice();
                ParseList(oslp, o15App, ospp15);
            }

            if (ospp14.Count > 0)
            {
                echoOffice();
                ParseList(oslp, o14App, ospp14);
            }

            if (hSLC != IntPtr.Zero)
            {
                CloseSL(hSLC);
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

#region SSSS
        public static string SlGetInfoIID(string SkuId)
        {
            Object[] parameters = new Object[] { hSLC, new Guid(SkuId), null };

            if ((int)Win32.GetMethod("SLGenerateOfflineInstallationId").Invoke(null, parameters) != 0)
            {
                return null;
            }
            else
            {
                return Marshal.PtrToStringUni((IntPtr)parameters[2]);
            }
        }

        public static string SlReturnData(int hrRet, uint tData, uint cData, IntPtr bData)
        {
            if (hrRet != 0 || cData == 0)
            {
                return null;
            }
            if (tData == 1)
            {
                return Marshal.PtrToStringUni(bData);
            }
            else if (tData == 4)
            {
                return Convert.ToString(Marshal.ReadInt32(bData));
            }
            else if (tData == 3 && cData == 8)
            {
                return Convert.ToString(Marshal.ReadInt64(bData));
            }
            else
            {
                return null;
            }
        }

        public static string SlGetInfoPKey(string PkeyId, string wszValue)
        {
            Object[] parameters = new Object[] { hSLC, new Guid(PkeyId), wszValue, null, null, null };

            int hrRet = (int)Win32.GetMethod("SLGetPKeyInformation").Invoke(null, parameters);

            return SlReturnData(hrRet, (uint)parameters[3], (uint)parameters[4], (IntPtr)parameters[5]);
        }

        public static string SlGetInfoSku(string SkuId, string wszValue)
        {
            Object[] parameters = new Object[] { hSLC, new Guid(SkuId), wszValue, null, null, null };

            int hrRet = (int)Win32.GetMethod("SLGetProductSkuInformation").Invoke(null, parameters);

            return SlReturnData(hrRet, (uint)parameters[3], (uint)parameters[4], (IntPtr)parameters[5]);
        }

        public static string SlGetInfoApp(string AppId, string wszValue)
        {
            Object[] parameters = new Object[] { hSLC, new Guid(AppId), wszValue, null, null, null };

            int hrRet = (int)Win32.GetMethod("SLGetApplicationInformation").Invoke(null, parameters);

            return SlReturnData(hrRet, (uint)parameters[3], (uint)parameters[4], (IntPtr)parameters[5]);
        }

        public static string SlGetInfoService(string wszValue)
        {
            Object[] parameters = new Object[] { hSLC, wszValue, null, null, null };

            int hrRet = (int)Win32.GetMethod("SLGetServiceInformation").Invoke(null, parameters);

            return SlReturnData(hrRet, (uint)parameters[2], (uint)parameters[3], (IntPtr)parameters[4]);
        }

        public static string SlGetInfoSvcApp(string strApp, string wszValue)
        {
            if (SLApp)
            {
                return SlGetInfoApp(strApp, wszValue);
            }
            else
            {
                return SlGetInfoService(wszValue);
            }
        }

        public static Hashtable SlGetInfoLicensing(string AppId, string SkuId)
        {
            Object[] parameters = new Object[] { hSLC, new Guid(AppId), new Guid(SkuId), IntPtr.Zero, null, null };

            int hrRet = (int)Win32.GetMethod("SLGetLicensingStatusInformation").Invoke(null, parameters);

            uint cStatus = (uint)parameters[4];
            if (hrRet != 0 || cStatus == 0)
            {
                return new Hashtable() { {"dwStatus", (int)0}, {"dwGrace", (int)0}, {"hrReason", (int)0}, {"qwValidity", (long)0} };
            }

            IntPtr pStatus = (IntPtr)parameters[5];
            IntPtr ppStatus = new IntPtr(pStatus.ToInt64() + (Int64)(40 * (cStatus - 1)));

            int dwStatus = Marshal.ReadInt32(ppStatus, 16);
            int dwGrace = Marshal.ReadInt32(ppStatus, 20);
            int hrReason = Marshal.ReadInt32(ppStatus, 28);
            long qwValidity = Marshal.ReadInt64(ppStatus, 32);
            if (dwStatus == 3)
            {
                dwStatus = 5;
            }
            if (dwStatus == 2)
            {
                if (hrReason == 0x4004F00D)
                {
                    dwStatus = 3;
                }
                else if (hrReason == 0x4004F065)
                {
                    dwStatus = 4;
                }
                else if (hrReason == 0x4004FC06)
                {
                    dwStatus = 6;
                }
            }

            return new Hashtable() {
                {"dwStatus", dwStatus},
                {"dwGrace", dwGrace},
                {"hrReason", hrReason},
                {"qwValidity", qwValidity}
            };
        }

        public static void SlGetInfoSLID(string AppId, ref List<Dictionary<string, string>> arrIDs)
        {
            Object[] parameters = new Object[] { hSLC, (uint)0, new Guid(AppId), (uint)1, null, null };

            int hrRet = (int)Win32.GetMethod("SLGetSLIDList").Invoke(null, parameters);

            uint cReturnIds = (uint)parameters[4];
            if (hrRet != 0 || cReturnIds == 0)
            {
                return;
            }
            IntPtr pReturnIds = (IntPtr)parameters[5];

            List<Dictionary<string, string>> a1List = new List<Dictionary<string, string>>(), a2List = new List<Dictionary<string, string>>(), a3List = new List<Dictionary<string, string>>(), a4List = new List<Dictionary<string, string>>();

            for (int i = 0; i < cReturnIds; i++)
            {
                byte[] bytes = new byte[16];
                Marshal.Copy((IntPtr)((Int64)pReturnIds + (Int64)(16 * i)), bytes, 0, 16);
                string actid = (new Guid(bytes)).ToString();
                string gPPK = SlGetInfoSku(actid, "pkeyId");
                string gAdd = SlGetInfoSku(actid, "DependsOn");
                if (ShowAll)
                {
                    if (String.IsNullOrEmpty(gPPK) && !String.IsNullOrEmpty(gAdd))
                    {
                        a1List.Add(new Dictionary<string, string>() { {"id", actid}, {"pk", string.Empty}, {"ex", "true"} });
                    }
                    if (String.IsNullOrEmpty(gPPK) && String.IsNullOrEmpty(gAdd))
                    {
                        a2List.Add(new Dictionary<string, string>() { {"id", actid}, {"pk", string.Empty}, {"ex", "false"} });
                    }
                }
                if (!String.IsNullOrEmpty(gPPK) && !String.IsNullOrEmpty(gAdd))
                {
                    a3List.Add(new Dictionary<string, string>() { {"id", actid}, {"pk", gPPK}, {"ex", "true"} });
                }
                if (!String.IsNullOrEmpty(gPPK) && String.IsNullOrEmpty(gAdd))
                {
                    a4List.Add(new Dictionary<string, string>() { {"id", actid}, {"pk", gPPK}, {"ex", "false"} });
                }
            }

            if (a1List.Count > 0)
            {
                arrIDs.AddRange(a1List);
            }
            if (a2List.Count > 0)
            {
                arrIDs.AddRange(a2List);
            }
            if (a3List.Count > 0)
            {
                arrIDs.AddRange(a3List);
            }
            if (a4List.Count > 0)
            {
                arrIDs.AddRange(a4List);
            }

            return;
        }

        public static void ParseList(string SLProduct, string strApp, List<Dictionary<string, string>> arrList)
        {
            foreach (Dictionary<string, string> item in arrList)
            {
                GetResult(SLProduct, strApp, item);
                Console.WriteLine(line3);
                if (!ShowAll) {Console.WriteLine();}
            }
        }
#endregion

#region WMI
        public static void CollectWmiProps(string filter, ref StringDictionary propColl)
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

        public static void DetectSubscription()
        {
            StringDictionary objSvc = new StringDictionary();
            try
            {
                CollectWmiProps("SELECT SubscriptionType, SubscriptionStatus, SubscriptionEdition, SubscriptionExpiry FROM SoftwareLicensingService", ref objSvc);
            }
            catch
            {
                return;
            }
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
#endregion

        public static void DetectAdbaClient(string strID)
        {
            StringDictionary objPrd = new StringDictionary();
            foreach (string strProp in propADBA)
            {
                objPrd.Add(strProp, SlGetInfoSku(strID, strProp));
            }
            Console.WriteLine("\r\nAD Activation client information:");
            Console.WriteLine("    Object Name: " + objPrd["ADActivationObjectName"]);
            Console.WriteLine("    Domain Name: " + objPrd["ADActivationObjectDN"]);
            Console.WriteLine("    CSVLK Extended PID: " + objPrd["ADActivationCsvlkPID"]);
            Console.WriteLine("    CSVLK Activation ID: " + objPrd["ADActivationCsvlkSkuID"]);
        }

        public static void DetectAvmClient(string strID)
        {
            StringDictionary objPrd = new StringDictionary();
            foreach (string strProp in propAVMA)
            {
                objPrd.Add(strProp, SlGetInfoSku(strID, strProp));
            }
            Console.WriteLine("\r\nAutomatic VM Activation client information:");
            if (!String.IsNullOrEmpty(objPrd["InheritedActivationId"]))
            {
                Console.WriteLine("    Guest IAID: " + objPrd["InheritedActivationId"]);
            }
            else
            {
                Console.WriteLine("    Guest IAID: Not Available");
            }
            if (!String.IsNullOrEmpty(objPrd["InheritedActivationHostMachineName"]))
            {
                Console.WriteLine("    Host machine name: " + objPrd["InheritedActivationHostMachineName"]);
            }
            else
            {
                Console.WriteLine("    Host machine name: Not Available");
            }
            if (!String.IsNullOrEmpty(objPrd["InheritedActivationHostDigitalPid2"]))
            {
                Console.WriteLine("    Host Digital PID2: " + objPrd["InheritedActivationHostDigitalPid2"]);
            }
            else
            {
                Console.WriteLine("    Host Digital PID2: Not Available");
            }
            string avmTime = objPrd["InheritedActivationActivationTime"];
            if (!String.IsNullOrEmpty(avmTime))
            {
                Console.WriteLine("    Activation time: {0}", DateTime.FromFileTime(Convert.ToInt64(avmTime)).ToString("yyyy-MM-dd hh:mm:ss tt"));
            }
            else
            {
                Console.WriteLine("    Activation time: Not Available");
            }
        }

        public static void DetectKmsServer(string strSLP, string strApp, bool isOld)
        {
            string IsKMS = SlGetInfoSvcApp(strApp, "IsKeyManagementService");
            if (String.IsNullOrEmpty(IsKMS) || IsKMS == "0") {return;}

            string kreg;
            if (isOld)
            {
                kreg = SLKeyPath;
            }
            else if (strSLP.Equals(oslp))
            {
                kreg = OPKeyPath;
            }
            else
            {
                kreg = SPKeyPath;
            }

            string regListening = GetRegString(kreg, "KeyManagementServiceListeningPort");
            uint regPublishing = GetRegDword(kreg, "DisableDnsPublishing", 0);
            uint regPriority   = GetRegDword(kreg, "EnableKmsLowPriority", 0);
            string kmsListening = String.IsNullOrEmpty(regListening) == true ? "1688" : (regListening == "0" ? "1688" : regListening);
            string kmsPublishing;
            string kmsPriority;
            if (regPublishing == 0)
            {
                kmsPublishing = "Enabled";
            }
            else
            {
                kmsPublishing = "Disabled";
            }
            if (regPriority != 0)
            {
                kmsPriority = "Low";
            }
            else
            {
                kmsPriority = "Normal";
            }

            StringDictionary objPrd = new StringDictionary();
            if (SLApp)
            {
                foreach (string strProp in propKMSServer)
                {
                    objPrd.Add(strProp, SlGetInfoApp(strApp, strProp));
                }
            }
            else
            {
                foreach (string strProp in propKMSServer)
                {
                    objPrd.Add(strProp, SlGetInfoService(strProp));
                }
            }

            string KMSRequests = objPrd["KeyManagementServiceTotalRequests"];
            bool NoRequests = String.IsNullOrEmpty(KMSRequests) || KMSRequests == "-1" || KMSRequests == (uint.MaxValue).ToString();

            Console.WriteLine("\r\nKey Management Service host information:");
            Console.WriteLine("    Current count: " + objPrd["KeyManagementServiceCurrentCount"]);
            Console.WriteLine("    Listening on Port: " + kmsListening);
            Console.WriteLine("    DNS publishing: " + kmsPublishing);
            Console.WriteLine("    KMS priority: " + kmsPriority);
            if (NoRequests)
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

        public static void DetectKmsClient(string strSLP, string strApp, string strID, bool isNT6, bool isNT8, bool isNT9, uint lState)
        {
            if (isNT8)
            {
                uint VLType;
                VLType = GetRegDword(SPKeyPath + "\\" + strApp + "\\" + strID, "VLActivationType", 0);
                if (VLType == 0) {VLType = GetRegDword(SPKeyPath + "\\" + strApp, "VLActivationType", 0);}
                if (VLType == 0) {VLType = GetRegDword(SPKeyPath, "VLActivationType", 0);}
                if (VLType > 3) {VLType = 0;}
                Console.WriteLine("Configured Activation Type: " + VLActTypes[VLType]);
            }
            Console.WriteLine();
            if (lState != 1)
            {
                Console.WriteLine("Please activate the product in order to update KMS client information values.");
                return;
            }

            StringDictionary objPrd = new StringDictionary();

            string kmsName, kmsPort, DiscName, DiscPort, intervalAct, intervalRen, kmsPID;
            string kmsDomain = string.Empty, kmsCaching = string.Empty;
            uint regCaching;

            if (isNT6)
            {
                foreach (string strProp in propKMSVista)
                {
                    objPrd.Add(strProp, SlGetInfoService(strProp));
                }
                string regPort = GetRegString(SLKeyPath, "KeyManagementServicePort");
                string regDscP = GetRegString(NSKeyPath, "DiscoveredKeyManagementServicePort");
                kmsPort = String.IsNullOrEmpty(regPort) == true ? "1688" : regPort;
                DiscPort = String.IsNullOrEmpty(regDscP) == true ? "1688" : regDscP;
                DiscName = GetRegString(NSKeyPath, "DiscoveredKeyManagementServiceName");
                kmsDomain = GetRegString(SLKeyPath, "KeyManagementServiceLookupDomain");
            }
            else
            {
                foreach (string strProp in propKMSClient)
                {
                    objPrd.Add(strProp, SlGetInfoSku(strID, strProp));
                }
                kmsPort = objPrd["KeyManagementServicePort"];
                DiscPort = objPrd["DiscoveredKeyManagementServicePort"];
                DiscName = objPrd["DiscoveredKeyManagementServiceName"];
                kmsDomain = objPrd["KeyManagementServiceLookupDomain"];
                if (strSLP.Equals(oslp))
                {
                    regCaching = GetRegDword(OPKeyPath, "DisableKeyManagementServiceHostCaching", 0);
                }
                else
                {
                    regCaching = GetRegDword(SPKeyPath, "DisableKeyManagementServiceHostCaching", 0);
                }
                if (Convert.ToBoolean(regCaching))
                {
                    kmsCaching = "Enabled";
                }
                else
                {
                    kmsCaching = "Disabled";
                }
            }

            objPrd.Add("ClientMachineID", SlGetInfoService("ClientMachineID"));
            intervalAct = objPrd["VLActivationInterval"];
            intervalRen = objPrd["VLRenewalInterval"];
            kmsPID = objPrd["CustomerPID"];
            kmsName = objPrd["KeyManagementServiceName"];

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

            string DiscIP = string.Empty;
            if (isNT9)
            {
                DiscIP = objPrd["DiscoveredKeyManagementServiceIpAddress"];
                if (!String.IsNullOrEmpty(DiscIP))
                {
                    DiscIP = "not available";
                }
            }

            Console.WriteLine("Key Management Service client information:");
            Console.WriteLine("    Client Machine ID (CMID): " + objPrd["ClientMachineID"]);
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

        public static void GetResult(string strSLP, string strApp, Dictionary<string, string> entry)
        {
            string licID = entry["id"];
            StringDictionary objPrd = new StringDictionary();
            foreach (string strProp in propPrd)
            {
                objPrd.Add(strProp, SlGetInfoSku(licID, strProp));
            }

            Hashtable LicStatus = SlGetInfoLicensing(strApp, licID);
            uint licState = Convert.ToUInt32(LicStatus["dwStatus"]);
            uint gprMnt = Convert.ToUInt32(LicStatus["dwGrace"]);
            int LicReason = (int)LicStatus["hrReason"];
            long EvaluationEndDate = (long)LicStatus["qwValidity"];

            string licName = objPrd["Name"];
            string licDesc = objPrd["Description"];
            string pkid = entry["pk"];
            bool isPPK = String.IsNullOrEmpty(pkid) == false;

            int add_on = licName.IndexOf("add-on for", StringComparison.OrdinalIgnoreCase);
            if (add_on != -1)
            {
                licName = licName.Substring(0, add_on + 7);
            }

            string licPHN = "empty";
            if (ShowDlv || ShowAll)
            {
                licPHN = SlGetInfoSku(licID, "msft:sl/EUL/PHONE/PUBLIC");
            }

            if (licState == 0 && !isPPK)
            {
                if (ShowAll) {Console.WriteLine();}
                Console.WriteLine("Name: " + licName);
                Console.WriteLine("Description: " + licDesc);
                Console.WriteLine("Activation ID: " + licID);
                Console.WriteLine("License Status: Unlicensed");
                if (licPHN != "empty")
                {
                    bool gPHN = String.IsNullOrEmpty(licPHN) != true;
                    Console.WriteLine("Phone activatable: " + gPHN.ToString());
                }
                return;
            }

            bool winID = (strApp.Equals(winApp));
            bool Vista = (winID && NT6 && !NT7);
            bool NT5 = (strSLP.Equals(wslp) && winbuild < 6001);
            bool win8 = (strSLP.Equals(wslp) && NT8);
            bool winPR = (winID && (entry["ex"]).Equals("false"));
            string reapp = winID == true ? "Windows" : "App";
            string prmnt = winPR == true ? "machine" : "product";

            string LicenseInf = string.Empty, LicenseMsg = string.Empty, ExpireMsg = string.Empty, actTag = string.Empty;
            bool cKmsServer = false, cKmsClient = false, cAvmClient = false;

            if (licDesc.Contains("VOLUME_KMSCLIENT")) {cKmsClient = true; actTag = "Volume";}
            if (licDesc.Contains("TIMEBASED_")) {actTag = "Timebased";}
            if (licDesc.Contains("VIRTUAL_MACHINE_ACTIVATION")) {cAvmClient = true; actTag = "Automatic VM";}
            if (!cKmsClient && licDesc.Contains("VOLUME_KMS")) {cKmsServer = true;}

            uint gprDay = Convert.ToUInt32(Math.Round(Convert.ToDouble(gprMnt / 1440)));
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
                LicenseInf = "Additional grace period (KMS license expired or hardware out of tolerance)";
                if (inGrace) {ExpireMsg = "Additional grace period" + " ends " + xpr;}
            }
            if (licState == 4)
            {
                LicenseInf = "Non-genuine grace period";
                if (inGrace) {ExpireMsg = LicenseInf + " ends " + xpr;}
            }
            if (licState == 5 && !NT5)
            {
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

            if (isPPK)
            {
                foreach (string strProp in propPkey)
                {
                    objPrd.Add(strProp, SlGetInfoPKey(pkid, strProp));
                }
            }

            string licPPK = objPrd["PartialProductKey"];
            string licCHN = objPrd["Channel"];
            string licEPID = objPrd["DigitalPID"];
            string licPID2 = objPrd["DigitalPID2"];

            string licIID = string.Empty;
            if (ShowIID && isPPK)
            {
                licIID = SlGetInfoIID(licID);
            }

            if (winPR && isPPK && !NT8)
            {
                string uxd = SlGetInfoSku(licID, "UXDifferentiator");
                primary.Add("aid", licID);
                primary.Add("ppk", licPPK);
                primary.Add("chn", licCHN);
                primary.Add("lst", licState);
                primary.Add("lcr", LicReason);
                primary.Add("ged", gprMnt);
                primary.Add("evl", EvaluationEndDate);
                primary.Add("dff", uxd);
            }

            string licTime = objPrd["TrustedTime"];
            string rearmApp = "-1", rearmSku = "-1", rearmSlp = "-1";
            if (ShowDlv)
            {
                if (win8)
                {
                    rearmSku = SlGetInfoSku(licID, "RemainingRearmCount");
                    rearmApp = SlGetInfoApp(strApp, "RemainingRearmCount");
                }
                else
                {
                    if ((winID && NT7) || strSLP.Equals(oslp))
                    {
                        rearmSlp = SlGetInfoApp(strApp, "RemainingRearmCount");
                    }
                    else
                    {
                        rearmSlp = SlGetInfoService("RearmCount");
                    }
                }
                if (String.IsNullOrEmpty(licTime))
                {
                    licTime = SlGetInfoSvcApp(strApp, "TrustedTime");
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
            if (!String.IsNullOrEmpty(licPPK)) {Console.WriteLine("Partial Product Key: " + licPPK);}
            Console.WriteLine("License Status: " + LicenseInf);
            if (!String.IsNullOrEmpty(LicenseMsg)) {Console.WriteLine(LicenseMsg);}
            if (licState != 0 && EvaluationEndDate != 0)
            {
                Console.WriteLine("Evaluation End Date: {0} UTC", DateTime.FromFileTimeUtc(EvaluationEndDate).ToString("yyyy-MM-dd hh:mm:ss tt"));
            }
            if (licState != 1 && licPHN != "empty")
            {
                bool gPHN = String.IsNullOrEmpty(licPHN) != true;
                Console.WriteLine("Phone activatable: " + gPHN.ToString());
            }

            if (ShowDlv)
            {
                if (String.IsNullOrEmpty(rearmSlp) != true && rearmSlp != "-1" && rearmSlp != (uint.MaxValue).ToString())
                {
                    Console.WriteLine("Remaining "+reapp+" rearm count: " + rearmSlp);
                }
                if (String.IsNullOrEmpty(rearmSku) != true && rearmSku != "-1" && rearmSku != (uint.MaxValue).ToString())
                {
                    Console.WriteLine("Remaining "+reapp+" rearm count: " + rearmApp);
                    Console.WriteLine("Remaining SKU rearm count: " + rearmSku);
                }
                if (licState != 0 && !String.IsNullOrEmpty(licTime))
                {
                    Console.WriteLine("Trusted time: {0}", DateTime.FromFileTime(Convert.ToInt64(licTime)).ToString("yyyy-MM-dd hh:mm:ss tt"));
                }
            }

            if (!isPPK)
            {
                return;
            }

            string licVLT = objPrd["VLActivationType"];
            if (win8 && licVLT == "1")
            {
                DetectAdbaClient(licID);
            }

            if (winID && cAvmClient)
            {
                DetectAvmClient(licID);
            }

            bool chkSub = (winPR && isSub);
            bool chkSLS = cKmsClient || cKmsServer || chkSub;
            if (!chkSLS)
            {
                if (!String.IsNullOrEmpty(ExpireMsg)) {Console.WriteLine("\r\n    " + ExpireMsg);}
                return;
            }

            if (cKmsClient)
            {
                DetectKmsClient(strSLP, strApp, licID, Vista, win8, (strSLP.Equals(wslp) && NT9), licState);
            }

            if (cKmsServer)
            {
                if (!String.IsNullOrEmpty(ExpireMsg)) {Console.WriteLine("\r\n    " + ExpireMsg);}
                DetectKmsServer(strSLP, strApp, (Vista || NT5));
            }
            else
            {
                if (!String.IsNullOrEmpty(ExpireMsg)) {Console.WriteLine("\r\n    " + ExpireMsg);}
            }

            if (chkSub)
            {
                DetectSubscription();
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
        public static string BoolToWStr(uint bVal)
        {
            if (bVal == 0) { return "FALSE"; } else { return "TRUE"; }
        }

        public static void PrintStateData()
        {
            Object[] parameters = new Object[] { "Security-SPP-Action-StateData", null, null, null };
            try
            {
                int result = (int)CAS.Program.Win32.GetMethod("SLGetWindowsInformation").Invoke(null, parameters);
                if (result != 0)
                    return;
            }
            catch
            {
                return;
            }

            IntPtr pwszStateData = (IntPtr)parameters[3];
            Console.WriteLine("    " + Marshal.PtrToStringUni(pwszStateData).Replace(";", "\n    "));
            Marshal.FreeHGlobal(pwszStateData);
            return;
        }

        public static void PrintLastActivationHResult()
        {
            Object[] parameters = new Object[] { "Security-SPP-LastWindowsActivationHResult", null, null, null };
            try
            {
                int result = (int)CAS.Program.Win32.GetMethod("SLGetWindowsInformation").Invoke(null, parameters);
                if (result != 0)
                    return;
            }
            catch
            {
                return;
            }

            IntPtr pdwLastHResult = (IntPtr)parameters[3];
            Console.WriteLine("    LastActivationHResult=0x{0:x8}", Marshal.ReadInt32(pdwLastHResult));
            Marshal.FreeHGlobal(pdwLastHResult);
            return;
        }

        public static void PrintLastActivationTime()
        {
            Object[] parameters = new Object[] { "Security-SPP-LastWindowsActivationTime", null, null, null };
            try
            {
                int result = (int)CAS.Program.Win32.GetMethod("SLGetWindowsInformation").Invoke(null, parameters);
                if (result != 0)
                    return;
            }
            catch
            {
                return;
            }

            IntPtr pqwLastTime = (IntPtr)parameters[3];
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
            Object[] parameters = new Object[] { null };
            try
            {
                int result = (int)CAS.Program.Win32.GetMethod("SLIsWindowsGenuineLocal").Invoke(null, parameters);
                if (result != 0)
                    return;
            }
            catch
            {
                return;
            }

            uint pdwGenuineState = (uint)parameters[0];
            if (pdwGenuineState < 5)
            {
                Console.WriteLine("    IsWindowsGenuine={0}", CAS.Program.SL_GENUINE_STATE[pdwGenuineState]);
            }
            else
            {
                Console.WriteLine("    IsWindowsGenuine={0}", pdwGenuineState);
            }
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

            int dwReturnCode = (int)parameters[1];
            int bDigitalLicense = (dwReturnCode >= 0 && dwReturnCode != 1) ? 1 : 0;
            Console.WriteLine("    IsDigitalLicense={0}", BoolToWStr((uint)bDigitalLicense));
            return;
        }

        public static void PrintSubscriptionStatus()
        {
            string pwszPolicy = CAS.Program.winbuild >= 15063 ? "ConsumeAddonPolicySet" : "Allow-WindowsSubscription";
            Object[] dwparam = new Object[] { pwszPolicy, null };
            try
            {
                int result = (int)CAS.Program.Win32.GetMethod("SLGetWindowsInformationDWORD").Invoke(null, dwparam);
                if (result != 0)
                    return;
            }
            catch
            {
                return;
            }

            uint dwSupported = (uint)dwparam[1];
            Console.WriteLine("    SubscriptionSupportedEdition={0}", BoolToWStr(dwSupported));

            Object[] parameters = new Object[] { null };
            try
            {
                int result = (int)CAS.Program.Win32.GetMethod("ClipGetSubscriptionStatus").Invoke(null, parameters);
                if (result != 0)
                    return;
            }
            catch
            {
                return;
            }

            IntPtr pStatus = (IntPtr)parameters[0];
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

        public static void ClicRun(bool DllDigital, bool DllSubscription)
        {
            Console.WriteLine("Client Licensing Check information:");

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

#region clc
namespace CLC
{
    public static class Program
    {
        public static string clcGetExpireKrn()
        {
            Object[] parameters = new Object[] { "Kernel-ExpirationDate", null, null, null };
            int hrRet = (int)CAS.Program.Win32.GetMethod("SLGetWindowsInformation").Invoke(null, parameters);

            uint cData = (uint)parameters[1];
            uint tData = (uint)parameters[2];
            if (hrRet != 0 || cData == 0 || tData != 3)
            {
                return null;
            }

            IntPtr bData = (IntPtr)parameters[3];
            short year = Marshal.ReadInt16(bData, 0);
            if (year == 0 || year == 1601)
            {
                return null;
            }
            else
            {
                return String.Format("{0}/{1}/{2}:{3}:{4}:{5}", year, Marshal.ReadInt16(bData, 2), Marshal.ReadInt16(bData, 4), Marshal.ReadInt16(bData, 6), Marshal.ReadInt16(bData, 8), Marshal.ReadInt16(bData, 10));
            }
        }

        public static string clcGetExpireSys()
        {
            long kuser = Marshal.ReadInt64((new IntPtr(0x7FFE02C8)));

            if (kuser == 0)
            {
                return null;
            }
            else
            {
                return DateTime.FromFileTimeUtc(kuser).ToString("yyyy/MM/dd:HH:mm:ss");
            }
        }

        public static string clcGetLicensingState(ref uint uiState)
        {
            if (uiState == 5)
            {
                uiState = 3;
            }
            else if (uiState == 3 || uiState == 4 || uiState == 6)
            {
                uiState = 2;
            }
            else if (uiState > 6)
            {
                uiState = 4;
            }

            return String.Format("{0}", CAS.Program.SLLICENSINGSTATUS[uiState]);
        }

        public static string clcGetGenuineState(string AppId)
        {
            Object[] parameters;
            int hrRet;
            uint indx;
            uint uiGenuine;

            if (CAS.Program.NT7)
            {
                parameters = new Object[] { null };
                hrRet = (int)CAS.Program.Win32.GetMethod("SLIsWindowsGenuineLocal").Invoke(null, parameters);
                indx = 0;
            }
            else
            {
                parameters = new Object[] { new Guid(AppId), null, IntPtr.Zero };
                hrRet = (int)CAS.Program.Win32.GetMethod("SLIsGenuineLocal").Invoke(null, parameters);
                indx = 1;
            }

            if (hrRet != 0)
            {
                uiGenuine = 4;
            }
            else
            {
                uiGenuine = (uint)parameters[indx];
            }

            if (uiGenuine < 5)
            {
                return String.Format("{0}", CAS.Program.SL_GENUINE_STATE[uiGenuine]);
            }
            else
            {
                return String.Format("{0}", uiGenuine);
            }
        }

        public static void ClcRun(Hashtable prs)
        {
            if (prs.Count == 0)
            {
                return;
            }

            uint uiState = (uint)prs["lst"];
            uint ged = (uint)prs["ged"];
            long evl = (long)prs["evl"];

            string lState = clcGetLicensingState(ref uiState);
            string uState = clcGetGenuineState(CAS.Program.winApp);
            string TbbKrn = clcGetExpireKrn();
            string TbbSys = clcGetExpireSys();
            string ked = string.Empty;
            if (!String.IsNullOrEmpty(TbbKrn))
            {
                ked = TbbKrn;
            }
            else if (!String.IsNullOrEmpty(TbbSys))
            {
                ked = TbbSys;
            }

            Console.WriteLine("Client Licensing Check information:");

            Console.WriteLine("    AppId={0}", CAS.Program.winApp);
            if (ged > 0)
            {
            Console.WriteLine("    GraceEndDate={0}", DateTime.UtcNow.AddMinutes(ged).ToString("yyyy/MM/dd:HH:mm:ss"));
            }
            if (!String.IsNullOrEmpty(ked))
            {
            Console.WriteLine("    KernelTimebombDate={0}", ked);
            }
            Console.WriteLine("    LastConsumptionReason=0x{0:x8}", prs["lcr"]);
            if (evl > 0)
            {
            Console.WriteLine("    LicenseExpirationDate={0}", DateTime.FromFileTimeUtc(evl).ToString("yyyy/MM/dd:HH:mm:ss"));
            }
            Console.WriteLine("    LicenseState={0}", lState);
            Console.WriteLine("    PartialProductKey={0}", prs["ppk"]);
            Console.WriteLine("    ProductKeyType={0}", prs["chn"]);
            Console.WriteLine("    SkuId={0}", prs["aid"]);
            Console.WriteLine("    uxDifferentiator={0}", prs["dff"]);
            Console.WriteLine("    IsWindowsGenuine={0}", uState);
        }
    }
}
#endregion
