using Dependencies.ClrPh;
using System.Diagnostics;
using System.Xml.Linq;

namespace BridgeBuilder
{
    internal class Program
    {
        static HashSet<string> PrivateFunctions = new HashSet<string>()
        {
            "DllCanUnloadNow",
            "DllGetClassObject",
            "DllInstall",
            "DllRegisterServer",
            "DllUnregisterServer"
        };

        const string clname = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\BuildTools\\VC\\Tools\\MSVC\\14.29.30133\\bin\\Hostx64\\x86\\cl.exe";
        const string clargs = "__NAME__.cpp /W4 /O2 /Ob2 /Oi /Ot /Oy /GT /GL /GF /GS- /Gy /fp:fast /GR- /LD /link /LARGEADDRESSAWARE /OPT:REF /OPT:ICF /LTCG /PDB:\"__NAME__.pdb\" /def:__NAME__.def /DEBUG /DLL /MACHINE:X86 /NODEFAULTLIB /entry:DllMain /subsystem:windows /IMPLIB:__NAME__.imp.lib kernel32.lib";
        const string ProgramHeader = """
            #include "stdafx.h"
            #pragma pack(1)

            HINSTANCE hLThis = 0;
            HINSTANCE hL = 0;
            FARPROC ptrs[__MAX__FUNCS__] = { 0 };
            TCHAR systemPath[MAX_PATH * 2] = { 0 };
            size_t systemLength = 0;
            BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
            {
            	if (reason == DLL_PROCESS_ATTACH)
            	{
            		hLThis = hInst;

            		if (!GetSystemDirectory(systemPath, MAX_PATH)) return FALSE;
                    systemLength = _tcslen(systemPath);
            		if (systemLength>0 && systemPath[systemLength-1]!='\\'){
                        if(systemLength<sizeof(systemPath)/sizeof(TCHAR)-1)
                        {
                            systemPath[systemLength-1]='\\';
                            systemPath[systemLength] = 0;
                        }else{
                            return FALSE;
                        }
                    }
            		if (StringCchCat(systemPath, sizeof(systemPath)/sizeof(TCHAR), "__DLL__PATH__") != S_OK) return FALSE;

            		hL = LoadLibrary(systemPath);
            		if (0 == hL) return FALSE;
            

            """;
        const string ProgramTailer = """
            	}
            	if (reason == DLL_PROCESS_DETACH)
            	{
            		FreeLibrary(hL);
            	}

            	return 1;
            }
            
            """;
        static int Main(string[] args)
        {
            if (args.Length == 0)
            {

            }
            else
            {
                var pe_path = Path.Combine(Environment.CurrentDirectory,args[0]);
                if(!File.Exists(pe_path))
                {
                    return -1;
                }
                PE pe=new (pe_path);
                if(pe.Load())
                {
                    const bool use32 = true;
                    var syspath = Environment.SystemDirectory.ToUpper();
                    if (use32 && syspath.EndsWith("\\SYSTEM32"))
                    {
                        syspath = Path.Combine(Path.GetDirectoryName(syspath), "SysWOW64");
                    }
                    var impexps = new Dictionary<string,List<PeExport>>();
                    var imps = pe.GetImports();
                    foreach(var imp in imps)
                    {
                        var path = Path.Combine(syspath, imp.Name);
                        var dll = new PE(path);
                        if (dll.Load())
                        {
                            var exps = dll.GetExports();
                            impexps.Add(imp.Name, exps);

                            dll.Unload();
                        }
                    }
                    pe.Unload();
                    foreach (var imp in imps)
                    {
                        if(impexps.TryGetValue(imp.Name, out var exps))
                        {
                            var name = Path.GetFileNameWithoutExtension(imp.Name);
                            var dn = Path.Combine(Environment.CurrentDirectory, name + ".dll");
                            var provider_dll_name = Path.GetFileNameWithoutExtension(dn) + ".org.dll";
                            var working_dll_path = Path.Combine(Environment.CurrentDirectory,
                                Path.GetFileNameWithoutExtension(dn) + ".dll");
                            var source_dll_path = Path.Combine(syspath, name + ".dll");
                            using (var defwriter = new StreamWriter(
                                Path.Combine(Environment.CurrentDirectory, name + ".def")))
                            {
                                defwriter.WriteLine($"LIBRARY \"{name}\"");
                                defwriter.WriteLine("EXPORTS");
                                var fn = Path.Combine(Environment.CurrentDirectory, name + ".cpp");
                                using (var codewriter = new StreamWriter(fn))
                                {
                                    var index = 0;
                                    codewriter.WriteLine(
                                        ProgramHeader
                                        .Replace("__DLL__PATH__", provider_dll_name)
                                        .Replace("__MAX__FUNCS__", $"{exps.Count}")
                                        );
                                    foreach (var expfunc in exps)
                                    {
                                        var funcordinal = expfunc.Ordinal;
                                        var funcname = expfunc.Name;
                                        if (expfunc.ExportByOrdinal)
                                        {
                                            funcname = "F_" + funcordinal;
                                            codewriter.WriteLine($"\t\tptrs[{index++}] = GetProcAddress(hL, (LPCSTR){funcordinal});");

                                        }
                                        else
                                        {
                                            codewriter.WriteLine($"\t\tptrs[{index++}] = GetProcAddress(hL, \"{funcname}\");");
                                        }
                                    }
                                    codewriter.WriteLine(ProgramTailer);
                                    index = 0;
                                    foreach (var expfunc in exps)
                                    {
                                        var funcordinal = expfunc.Ordinal;
                                        var funcname = expfunc.Name;
                                        if (expfunc.ExportByOrdinal)
                                        {
                                            funcname = "F_" + funcordinal;
                                        }

                                        var bridged_funcname = funcname.Replace('?','_').Replace('@','_').Replace('$', '_');
                                        var tail = "";
                                        if (PrivateFunctions.Contains(funcname))
                                        {
                                            tail = "PRIVATE";
                                        }

                                        if (funcordinal == 0 || tail!="")
                                        {
                                            defwriter.WriteLine($"{funcname}=__BRIDGE_{bridged_funcname} {tail}");
                                        }
                                        else
                                        {
                                            defwriter.WriteLine($"{funcname}=__BRIDGE_{bridged_funcname} @{funcordinal} {tail}");
                                        }
                                        //Console.WriteLine($"Processing {bridged_funcname}");
                                        codewriter.WriteLine($"extern \"C\" __declspec(naked) void __stdcall __BRIDGE_{bridged_funcname}()");
                                        codewriter.WriteLine("{");
                                        codewriter.WriteLine("\t__asm");
                                        codewriter.WriteLine("\t{");
                                        codewriter.WriteLine($"\t\tjmp ptrs[{index++}*4];");
                                        codewriter.WriteLine("\t}");
                                        codewriter.WriteLine("}");
                                    }

                                }
                            }
                            using var ret = Process.Start(clname,clargs.Replace("__NAME__", 
                                Path.Combine(Environment.CurrentDirectory,name)));
                            ret.WaitForExit();
                            //copy dll from system to ".org.dll"
                            if (File.Exists(source_dll_path))
                            {
                                File.Copy(source_dll_path, provider_dll_name, true);
                            }
                            else
                            {
                                Console.WriteLine($"File {source_dll_path} does not exist!");
                            }
                        }
                    }
                   
                }


            
            }
            return 0;
        }
    }
}