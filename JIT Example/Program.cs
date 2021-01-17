using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace JIT_Example
{

    class Program
    {
        [DllImport("Clrjit.dll", CallingConvention = CallingConvention.StdCall, PreserveSig = true)]
        static extern IntPtr getJit();

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
           uint flNewProtect, out uint lpflOldProtect);

        delegate IntPtr getJitDel();

        public static Context.delCompileMethod OrigCompileMethod;


        unsafe static void Main(string[] args)
        {
            uint old;
            Context.delCompileMethod hookedCompileMethod = HookedCompileMethod;
            var vTable = getJit(); //ICorJitCompiler pointer'ı alındı
            var compileMethodPtr = Marshal.ReadIntPtr(vTable); //İçerisindeki ilk pointer okundu.
            OrigCompileMethod = (Context.delCompileMethod)Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(compileMethodPtr), typeof(Context.delCompileMethod)); //Orjinal compileMethod fonksiyonu Delegate türünde yüklendi.
            //Bizim iznimizde tekrardan çalıştırmak istersek orjinal fonksiyonu yerine koymak zorunda olduğumuz için
            if (!VirtualProtect(compileMethodPtr, (uint)IntPtr.Size, 0x40, out old)) //VirtualProtect ile bölgenin izinleri execute read write izni olarak değiştirildi
                    return;

            RuntimeHelpers.PrepareDelegate(hookedCompileMethod);//Belirtilen temsilcinin kısıtlanmış bir yürütme bölgesine (CER) eklenmek üzere hazırlanması gerektiğini gösterir.
            RuntimeHelpers.PrepareDelegate(OrigCompileMethod);
            //Bunları koymadan çalıştırırsanız göreceksiniz ki program stackoverflow exception'a düşecek. Sonsuz döngüye girmemesi için koyuyoruz.
            Marshal.WriteIntPtr(compileMethodPtr, Marshal.GetFunctionPointerForDelegate(hookedCompileMethod)); //Fake fonksiyonumuzun adresini alıp compileMethod pointer'ının yerine yazdırdık.
            VirtualProtect(compileMethodPtr, (uint)IntPtr.Size,
                old, out old);//İzinleri eski haline döndürüyoruz.

            Console.WriteLine(testFunc()); //Bakalım çalışıyor mu

            if (!VirtualProtect(compileMethodPtr, (uint)IntPtr.Size, 0x40, out old)) //VirtualProtect ile bölgenin izinleri execute read write izni olarak değiştirildi
                return; //Şimdi orjinal compileMethod'u yazdıracağımız için tekrar izinleri düzenliyoruz execute read write olarak.

            Marshal.WriteIntPtr(compileMethodPtr, Marshal.GetFunctionPointerForDelegate(OrigCompileMethod)); //Orjinal compileMethod'u yazdırdık fonksiyonumuzu normal çalıştırmak için.

            Console.WriteLine("Şuan çalışmıyor");
            Console.ReadKey();
        }

        public static string testFunc()
        {
            return "Çalışıyorrr";
        }

        private static unsafe int HookedCompileMethod(IntPtr thisPtr, [In] IntPtr corJitInfo,
 [In] Context.CorMethodInfo* methodInfo, Context.CorJitFlag flags,
[Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode)
        {
            int token;
            Console.WriteLine("Compilation:\r\n");
            Console.WriteLine("Token: " + (token = (0x06000000 + *(ushort*)methodInfo->methodHandle)).ToString("x8"));
            Console.WriteLine("Name: " + typeof(Program).Module.ResolveMethod(token).Name);
            Console.WriteLine("Body size: " + methodInfo->ilCodeSize);

            var bodyBuffer = new byte[methodInfo->ilCodeSize];
            Marshal.Copy(methodInfo->ilCode, bodyBuffer, 0, bodyBuffer.Length);

            Console.WriteLine("Body: " + BitConverter.ToString(bodyBuffer));

            return OrigCompileMethod(thisPtr, corJitInfo, methodInfo, flags, nativeEntry, nativeSizeOfCode);
        }

    }
}
