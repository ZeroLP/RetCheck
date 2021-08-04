using System;
using System.Runtime.InteropServices;
using RetCheck.Tools;

namespace RetCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            SampleClass.Method1(123);

            Console.ReadLine();
        }

        static class SampleClass
        {
            public static void Method1(int a1)
            {
                var retAddr = NativeMemory.GetReturnAddress();

                Console.WriteLine($"Function address: 0x{NativeMemory.GetFunctionAddress():X}");

                a1 += a1;

                if (!IsReturnAddressInBound(NativeMemory.GetFunctionAddress(), retAddr))
                {
                    Console.WriteLine("Invalid return address.");
                    return;
                }

                Console.WriteLine($"Processed with {a1}.");
            }

            private static bool IsReturnAddressInBound(nint funcAddr, nint retAddr)
            {
                var currProc = System.Diagnostics.Process.GetCurrentProcess();
                NativeImport.GetModuleInformation(currProc.Handle, currProc.MainModule.BaseAddress, out var modInfo, (uint)Marshal.SizeOf(new NativeImport.NativeStructs.MODULEINFO()));

                Console.WriteLine($"retAddr: 0x{retAddr:X} | baseAddr: {currProc.MainModule.BaseAddress:X} | currModSize: {modInfo.SizeOfImage:X} " +
                                  $"| calcModuleRuntimeSize: {((nint)currProc.MainModule.BaseAddress + modInfo.SizeOfImage):X}" +
                                  $"\n| difference between retAddr and calcModuleRuntimeSize: {(retAddr - ((nint)currProc.MainModule.BaseAddress + modInfo.SizeOfImage)):X}");

                /*if (retAddr >= currProc.MainModule.BaseAddress 
                 && retAddr <= ((nint)currProc.MainModule.BaseAddress + modInfo.SizeOfImage))*/
                if(funcAddr == retAddr) //this is very ghetto way of checking the clarity and probably will break when it's been called by a method that was JMP'ed from a label.
                    return true;
                else
                    return false;
            }
        }
    }
}
