using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace RetCheck.Tools
{
    public class NativeMemory
    {
        //[SuppressGCTransition] //Stops the GC and CLR from swinging around the memory of this function. Not really supported in .NET5 for delegate* at this stage.
        public static nint GetFunctionAddress()
        {
            byte[] currentFuncAddrInstructions = new byte[]
            {
#if AnyCPU || x64
                0x48, 0x8B, 0x04, 0x24,        //mov rax, [rsp]    
                0xC3                           //ret
#endif

#if x86
                0x8B, 0x04, 0x24,              //mov eax, [esp]
                0xC3                           //ret
#endif
            };

            unsafe
            {
                fixed (void* iPtr = currentFuncAddrInstructions)
                {

                    if (!NativeImport.VirtualProtect((IntPtr)iPtr, (nuint)currentFuncAddrInstructions.Length, NativeImport.NativeStructs.MemoryProtection.ExecuteReadWrite, out var oldProtection))
                        throw new Exception($"Failed to change protection to ExecuteReadWrite at: 0x{(nint)iPtr:X}");

                    var funcAddr = ((delegate* unmanaged[Stdcall]<nint>)iPtr)();

                    if (!NativeImport.VirtualProtect((IntPtr)iPtr, (nuint)currentFuncAddrInstructions.Length, oldProtection, out var temp))
                        throw new Exception($"Failed to change protection back to {oldProtection} at: 0x{(nint)iPtr:X}");

                    return funcAddr;
                }
            }
        }


        //[SuppressGCTransition] //Stops the GC and CLR from swinging around the memory of this function. Not really supported in .NET5 for delegate* at this stage.
        public unsafe static nint GetReturnAddress()
        {
            byte[] retAddrInstructions = new byte[]
            {
#if AnyCPU || x64
                0x55,                       //push rbp
                0x48, 0x89, 0xE5,           //mov rbp, rsp

                0x48, 0x8B, 0x45, 0x08,     //mov rax, [rbp + 8]

                0x48, 0x89, 0xEC,           //mov rsp, rbp
                0x5D,                       //pop rbp
                0xC3                        //ret
#endif

#if x86
                0x55,                       //push ehp
                0x89, 0xE5,                 //mov ebp, esp

                0x8B, 0x45, 0x04,           //mov eax, [ebp + 4]

                0x8B, 0xE5,                 //mov esp, ebp
                0x5D,                       //pop ebp
                0xC3                        //ret
#endif
            };

            fixed (void* iPtr = retAddrInstructions)
            {
                if (!NativeImport.VirtualProtect((IntPtr)iPtr, (nuint)retAddrInstructions.Length, NativeImport.NativeStructs.MemoryProtection.ExecuteReadWrite, out var oldProtection))
                    throw new Exception($"Failed to change protection to ExecuteReadWrite at: 0x{(nint)iPtr:X}");

                var retAddr = ((delegate* unmanaged[Stdcall]<nint>)iPtr)();

                if (!NativeImport.VirtualProtect((IntPtr)iPtr, (nuint)retAddrInstructions.Length, oldProtection, out var temp))
                    throw new Exception($"Failed to change protection back to {oldProtection} at: 0x{(nint)iPtr:X}");

                return retAddr;
            }
        }
    }
}
