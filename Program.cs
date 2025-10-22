using HarmonyLib;
using Mono.Cecil;
using NetRunner;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using static HarmonyLib.Code;

namespace NetRunner
{
    /// <summary>
    /// Entry point and main program logic for NetRunner.
    /// Parses arguments, configures logging and runtime options.
    /// </summary>
    class Program
    {
        private static readonly object LogLock = new object();
        private static string LogPath;
        public static bool ShowStack = false;

        private static readonly string[] BannedNamespaces = {
            "System",
            "Microsoft",
            "Mono",
            "HarmonyLib",
            "Internal",
            "Runtime",
            "__",
            "<",
            "Windows.",
            "EmptyArray",
            "AssemblyRef",
            "FXAssembly",
            "ThisAssembly"
        };

        /// <summary>
        /// Parse command-line arguments, validate inputs and start the runner.
        /// </summary>
        /// <param name="args">Array of command-line arguments passed to the program.</param>
        static int Main(string[] args)
        {
            string methodsFile = null;
            string asmPath = null;
            string entryPoint = null;
            string logPath = null;

            // Parse arguments
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--methods" && i + 1 < args.Length)
                {
                    methodsFile = args[++i];
                }
                else if (args[i] == "--log" && i + 1 < args.Length)
                {
                    logPath = args[++i];
                }
                else if (args[i] == "--stack")
                {
                    ShowStack = true;
                }
                else if (args[i] == "--help" || args[i] == "-h")
                {
                    ShowUsage();
                    return 0;
                }
                else if (asmPath == null)
                {
                    asmPath = args[i];
                }
                else if (entryPoint == null)
                {
                    entryPoint = args[i];
                }
            }

            if (asmPath == null)
            {
                Console.WriteLine("[!] Usage: NetRunner.exe [--methods methodsFile.txt] [--log logFile.log] [--stack] assembly.dll [Namespace.Class::Method]");
                return 1;
            }

            if (!File.Exists(asmPath))
            {
                Console.WriteLine($"[!] {asmPath} does not exist");
                return 1;
            }

            if (methodsFile != null && !File.Exists(methodsFile))
            {
                Console.WriteLine($"[!] Methods file {methodsFile} does not exist");
                return 1;
            }

            LogPath = logPath ?? Path.Combine(AppContext.BaseDirectory, "tracer.log");

            return NetRun(asmPath, methodsFile, entryPoint);
        }

        /// <summary>
        /// Perform runtime initialization, load assembly, and coordinate patching and invocation.
        /// </summary>
        /// <param name="asmPath">Path to the target assembly to load and instrument.</param>
        /// <param name="methodsFile">Optional path to a file listing additional methods to patch.</param>
        /// <param name="entryPoint">Optional explicit entry point in format Namespace.Type::Method.</param>
        private static int NetRun(string asmPath, string methodsFile = null, string entryPoint = null)
        {
            Log($"== NetRunner started {DateTime.UtcNow:O} ==\n");

            AppDomain.CurrentDomain.AssemblyResolve += ResolveHandler;

            var asm = Assembly.LoadFrom(asmPath);

            var harmony = new Harmony("net.tracer.harmony");
            var patchPrefix = typeof(TracerHooks).GetMethod(nameof(TracerHooks.Prefix), BindingFlags.Static | BindingFlags.Public);
            var patchPostfixVoid = new HarmonyMethod(typeof(TracerHooks).GetMethod("PostfixVoid"));
            var patchPostfixResult = new HarmonyMethod(typeof(TracerHooks).GetMethod("PostfixResult"));

            PatchMethods(asmPath, asm, harmony, patchPrefix, patchPostfixVoid, patchPostfixResult, methodsFile);
            InvokeEntryPoint(asm, entryPoint);

            return 0;
        }

        /// <summary>
        /// Patch methods in the target assembly and referenced assemblies according to configuration.
        /// </summary>
        /// <param name="asmPath">Path to the target assembly file used for dependency scanning.</param>
        /// <param name="asm">Loaded Assembly instance of the target assembly.</param>
        /// <param name="harmony">Harmony instance used to apply patches.</param>
        /// <param name="patchPrefix">MethodInfo for the prefix hook to apply.</param>
        /// <param name="patchPostfixVoid">HarmonyMethod for postfix hooks on void methods.</param>
        /// <param name="patchPostfixResult">HarmonyMethod for postfix hooks that capture results.</param>
        /// <param name="methodsFile">Optional methods file containing extra methods to patch.</param>
        static void PatchMethods(string asmPath, Assembly asm, Harmony harmony, MethodInfo patchPrefix, HarmonyMethod patchPostfixVoid, HarmonyMethod patchPostfixResult, string methodsFile)
        {
            // Assembly load hook
            var asmType = typeof(Assembly);
            var loadBytes = asmType.GetMethod("Load", new[] { typeof(byte[]) });
            var prefix = new HarmonyMethod(typeof(LoadHooks).GetMethod(nameof(LoadHooks.Prefix)));
            new Harmony("net.tracer.loadhook").Patch(loadBytes, prefix);

            // Referenced methods
            var refs = GetReferencedMethods(asmPath);
            foreach (var name in asm.GetReferencedAssemblies())
            {
                try
                {
                    var dep = Assembly.Load(name);
                    PatchReferencedMethods(harmony, dep, refs);
                }
                catch { }
            }

            // Internal methods
            PatchAssemblyMethods(asm, harmony, patchPrefix, patchPostfixVoid, patchPostfixResult);

            // Handle methods file if provided
            if (methodsFile != null)
            {
                PatchMethodsFromFile(methodsFile, harmony);
            }

            Log($"\nPatched assembly: {asm.FullName}");
            Log($"Tracer ready. Logging to {LogPath}\n");
            Log($"=====================================================\n");
        }

        /// <summary>
        /// Invoke the specified entry point or auto-detect and invoke Main.
        /// </summary>
        /// <param name="asm">Loaded target Assembly in which to locate the entry point.</param>
        /// <param name="entryPoint">Optional entry point in the form Namespace.Type::Method; if null, attempts to find Main.</param>
        static void InvokeEntryPoint(Assembly asm, string entryPoint)
        {
            if (entryPoint == null)
            {
                // Detect main method automatically and invoke
                var mainType = asm.GetTypes().FirstOrDefault(t => t.GetMethod("Main", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static) != null);
                if (mainType != null)
                {
                    var mainMethod = mainType.GetMethod("Main", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                    Log($"Invoking {mainType.FullName}::Main\n");
                    try
                    {
                        var result = mainMethod.Invoke(null, mainMethod.GetParameters().Length == 0 ? null : CreateDefaultArguments(mainMethod.GetParameters()));
                        Log($"Invoked {mainType.FullName}::Main -> result: {JsonSerializer.Serialize(result)}");
                    }
                    catch (TargetInvocationException tie)
                    {
                        Log($"[!] Invocation threw: {tie.InnerException?.Message ?? tie.Message}");
                    }
                }
                else
                {
                    Log("[!] No entry point specified and no Main method found.");
                }
            }
            else
            {
                // Execute the entrypoint method if specified
                var token = entryPoint.Split(new[] { "::" }, StringSplitOptions.None);
                if (token.Length == 2)
                {
                    var tname = token[0];
                    var mname = token[1];
                    var t = asm.GetType(tname, throwOnError: false, ignoreCase: false);
                    if (t != null)
                    {
                        var mi = t.GetMethod(mname, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);
                        if (mi != null)
                        {
                            Log($"Invoking {tname}::{mname}\n");
                            object inst = null;
                            if (!mi.IsStatic)
                            {
                                var ctor = t.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).FirstOrDefault();
                                if (ctor != null) inst = ctor.Invoke(Array.Empty<object>());
                            }

                            try
                            {
                                var result = mi.Invoke(inst, mi.GetParameters().Length == 0 ? null : CreateDefaultArguments(mi.GetParameters()));
                                Log($"Invoked {tname}::{mname} -> result: {JsonSerializer.Serialize(result)}");
                            }
                            catch (TargetInvocationException tie)
                            {
                                Log($"[!] Invocation threw: {tie.InnerException?.Message ?? tie.Message}");
                            }
                        }
                        else Log($"[!] Method not found: {mname}");
                    }
                    else Log($"[!] Type not found: {tname}");
                }
            }
        }

        /// <summary>
        /// Print usage information to the console.
        /// </summary>
        static void ShowUsage()
        {
            Console.WriteLine("Usage:\nNetRunner.exe [--methods methodsFile.txt] [--log logFile.log] [--stack] assembly.dll [Namespace.Class::Method]\n");
            Console.WriteLine("--methods file.txt      : Optional file containing additional methods to trace");
            Console.WriteLine("--log file.log          : Optional custom log file path(default: `./ tracer.log`)");
            Console.WriteLine("--stack                 : Enable stack trace logging for each method call");
            Console.WriteLine("assembly.dll            : Target assembly to analyze");
            Console.WriteLine("Namespace.Class::Method : Entry point method to invoke(optional)");
        }

        /// <summary>
        /// Determine whether a type is a banned/ignored name.
        /// </summary>
        /// <param name="t">Type to evaluate against the banned name list.</param>
        static bool IsBanned(Type t)
        {
            var ns = t.FullName;
            foreach (var b in BannedNamespaces)
                if (ns.StartsWith(b, StringComparison.Ordinal)) return true;
            return false;
        }

        /// <summary>
        /// Scan the assembly and return a set of referenced method signatures.
        /// </summary>
        /// <param name="asmPath">Filesystem path of the assembly to scan with Mono.Cecil.</param>
        /// <returns>Set of tuples describing referenced methods: (DeclType, Method, AsmName).</returns>
        static HashSet<(string DeclType, string Method, string AsmName)> GetReferencedMethods(string asmPath)
        {
            var set = new HashSet<(string, string, string)>();
            var module = ModuleDefinition.ReadModule(asmPath);
            foreach (var type in module.Types)
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    foreach (var ins in method.Body.Instructions)
                    {
                        if (ins.OpCode.Code == Mono.Cecil.Cil.Code.Call || ins.OpCode.Code == Mono.Cecil.Cil.Code.Callvirt)
                        {
                            if (ins.Operand is MethodReference mr)
                            {
                                var asmName = mr.DeclaringType.Scope.Name;
                                set.Add((mr.DeclaringType.FullName, mr.Name, asmName));
                            }
                        }
                    }
                }
            }
            return set;
        }

        /// <summary>
        /// Patch referenced external methods that are called by the target assembly.
        /// </summary>
        /// <param name="harmony">Harmony instance used to apply patches.</param>
        /// <param name="a">Assembly containing candidate referenced methods to patch.</param>
        /// <param name="refs">Set of referenced method signatures discovered in the target assembly.</param>
        static void PatchReferencedMethods(Harmony harmony, Assembly a, HashSet<(string DeclType, string Method, string AsmName)> refs)
        {
            foreach (var t in a.GetTypes())
            {
                if (IsBanned(t)) continue;

                foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
                {
                    if (m.Name.StartsWith("op_")) continue;

                    //var id = (t.FullName, m.Name, a.GetName().Name);
                    //if (!refs.Contains(id)) continue; // skip if assembly never calls it
                    try
                    {
                        var pre = new HarmonyMethod(typeof(TracerHooks).GetMethod(nameof(TracerHooks.Prefix)));
                        var post = new HarmonyMethod(typeof(TracerHooks).GetMethod(
                            m.ReturnType == typeof(void) ? "PostfixVoid" : "PostfixResult"));
                        harmony.Patch(m, pre, post);
                        Program.Log($"[Referenced] Hooked {t.FullName}.{m.Name}");
                    }
                    catch (Exception ex)
                    {
                        Program.Log($"[Hook fail] {t.FullName}.{m.Name}: {ex.Message}");
                    }
                }
            }
        }

        /// <summary>
        /// Patch additional methods listed in a file.
        /// </summary>
        /// <param name="methodsFile">Path to the file containing extra method identifiers (Namespace.Type::Method).</param>
        /// <param name="harmony">Harmony instance used to apply patches to the listed methods.</param>
        static void PatchMethodsFromFile(string methodsFile, Harmony harmony)
        {
            var lines = File.ReadAllLines(methodsFile)
                            .Select(x => x.Trim())
                            .Where(x => !string.IsNullOrWhiteSpace(x) && !x.StartsWith("#"))
                            .ToArray();

            foreach (var line in lines)
            {
                try
                {
                    var split = line.Split(new[] { "::" }, StringSplitOptions.None);
                    if (split.Length != 2) continue;

                    var typeName = split[0];
                    var methodName = split[1];

                    var t = Type.GetType(typeName, throwOnError: false);
                    if (t == null)
                    {
                        Log($"[Extra] Type not found: {typeName}");
                        continue;
                    }

                    var methods = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
                                   .Where(m => m.Name == methodName)
                                   .ToArray();

                    if (methods.Length == 0)
                    {
                        Log($"[Extra] Method not found: {typeName}::{methodName}");
                        continue;
                    }

                    foreach (var mi in methods)
                    {
                        try
                        {
                            var prefix = new HarmonyMethod(typeof(TracerHooks).GetMethod(nameof(TracerHooks.Prefix)));
                            var postfix = mi.ReturnType == typeof(void)
                                ? new HarmonyMethod(typeof(TracerHooks).GetMethod("PostfixVoid"))
                                : new HarmonyMethod(typeof(TracerHooks).GetMethod("PostfixResult"));
                            harmony.Patch(mi, prefix, postfix);
                            Log($"[Extra] Hooked {typeName}.{mi.Name}");
                        }
                        catch (Exception ex)
                        {
                            Log($"[Extra] Failed to patch {typeName}.{mi.Name}: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log($"[Extra] Parse error: {line} -> {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Patch methods defined in the target assembly.
        /// </summary>
        /// <param name="asm">Loaded target Assembly whose types/methods should be instrumented.</param>
        /// <param name="harmony">Harmony instance used to apply patches.</param>
        /// <param name="patchPrefix">MethodInfo for the prefix hook to apply to each method.</param>
        /// <param name="patchPostfixVoid">HarmonyMethod for postfix hooks applied to void-returning methods.</param>
        /// <param name="patchPostfixResult">HarmonyMethod for postfix hooks applied to result-returning methods.</param>
        static void PatchAssemblyMethods(Assembly asm, Harmony harmony, MethodInfo patchPrefix, HarmonyMethod patchPostfixVoid, HarmonyMethod patchPostfixResult)
        {
            foreach (var type in asm.GetTypes())
            {
                // skip compiler-generated closures
                if (type.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), inherit: false)) continue;

                var methods = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly);
                foreach (var method in methods)
                {
                    try
                    {
                        if (method.IsAbstract) continue;
                        if (method.IsGenericMethodDefinition) continue;

                        // skip property/event synthetic methods 
                        if (method.Name.StartsWith("get_") || method.Name.StartsWith("set_") || method.Name.StartsWith("add_") || method.Name.StartsWith("remove_")) { /* trace if wanted */ }

                        var prefix = new HarmonyMethod(patchPrefix);
                        var postfix = method.ReturnType == typeof(void) ? patchPostfixVoid : patchPostfixResult;

                        harmony.Patch(method, prefix, postfix);
                        Log($"[Internal] Hooked {type.FullName}.{method.Name}");
                    }
                    catch (Exception ex)
                    {
                        Log($"Failed to patch {type.FullName}.{method.Name}: {ex.Message}");
                    }
                }
            }
        }

        /// <summary>
        /// Create default argument instances for invoking methods.
        /// </summary>
        /// <param name="pis">Array of ParameterInfo describing parameters for which default values should be created.</param>
        /// <returns>Array of objects representing default values for each parameter.</returns>
        static object[] CreateDefaultArguments(ParameterInfo[] pis)
        {
            var arr = new object[pis.Length];
            for (int i = 0; i < pis.Length; i++)
            {
                var p = pis[i].ParameterType;
                arr[i] = p.IsValueType ? Activator.CreateInstance(p) : null;
            }
            return arr;
        }

        /// <summary>
        /// Resolve assembly dependencies from the application directory.
        /// </summary>
        /// <param name="sender">Sender of the ResolveEvent (AppDomain).</param>
        /// <param name="args">ResolveEventArgs containing the name of the assembly to resolve.</param>
        /// <returns>Resolved Assembly if found in probes; otherwise null.</returns>
        static Assembly ResolveHandler(object sender, ResolveEventArgs args)
        {
            // Try load dependency from same folder as tracer or target assembly folder.
            var name = new AssemblyName(args.Name).Name + ".dll";
            var probe = Path.Combine(AppContext.BaseDirectory, name);
            if (File.Exists(probe)) return Assembly.LoadFrom(probe);
            return null;
        }

        /// <summary>
        /// Thread-safe logging to console and log file.
        /// </summary>
        /// <param name="text">Text to append to the console and log file.</param>
        public static void Log(string text)
        {
            lock (LogLock)
            {
                Console.WriteLine(text);
                File.AppendAllText(LogPath, text + "\n");
            }
        }
    }

    /// <summary>
    /// Hooks used by Harmony to trace calls and returns.
    /// </summary>
    public static class TracerHooks
    {
        /// <summary>
        /// Prefix executed before target method; starts timing and logs call details.
        /// </summary>
        /// <param name="__originalMethod">MethodBase of the method being invoked.</param>
        /// <param name="__instance">Instance object for instance methods, or null for static methods.</param>
        /// <param name="__args">Array of argument values passed to the method.</param>
        /// <param name="__state">Out parameter used to store per-call state (Stopwatch) for the postfix.</param>
        public static void Prefix(MethodBase __originalMethod, object __instance, object[] __args, out object __state)
        {
            __state = System.Diagnostics.Stopwatch.StartNew();

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"CALL {__originalMethod.DeclaringType?.FullName}.{__originalMethod.Name}");

            if (__args != null && __args.Length > 0)
            {
                sb.AppendLine("\tARGS :");
                for (int i = 0; i < __args.Length; i++)
                {
                    string val = SafeJson(__args[i]);
                    sb.AppendLine($"\t\t[{i}] {val}");
                }
            }
            else sb.AppendLine("\tARGS : (none)");

            var st = new System.Diagnostics.StackTrace(skipFrames: 1, fNeedFileInfo: false);
            var frames = st.GetFrames();
            if (Program.ShowStack && frames != null && frames.Length > 0)
            {
                sb.AppendLine("\tSTACK :");
                int show = Math.Min(6, frames.Length);
                for (int i = 0; i < show; i++)
                {
                    var mf = frames[i].GetMethod();
                    sb.AppendLine($"\t\t{mf?.DeclaringType?.FullName}.{mf?.Name}");
                }
            }

            var logged = sb.ToString();
            if (logged.Length > 200)
                Program.Log($"{logged.Substring(0, 200)} (Truncated)");
            else
                Program.Log(logged);
        }

        /// <summary>
        /// Postfix for non-void methods; forwards to FinalizeLog.
        /// </summary>
        /// <param name="__originalMethod">MethodBase of the method being invoked.</param>
        /// <param name="__instance">Instance object for instance methods, or null for static methods.</param>
        /// <param name="__args">Array of argument values passed to the method.</param>
        /// <param name="__state">Per-call state previously stored in Prefix.</param>
        /// <param name="__result">Result returned by the target method.</param>
        public static void PostfixResult(MethodBase __originalMethod, object __instance, object[] __args, object __state, object __result)
        {
            FinalizeLog(__originalMethod, __state, __result, false);
        }

        /// <summary>
        /// Postfix for void methods; forwards to FinalizeLog.
        /// </summary>
        /// <param name="__originalMethod">MethodBase of the method being invoked.</param>
        /// <param name="__instance">Instance object for instance methods, or null for static methods.</param>
        /// <param name="__args">Array of argument values passed to the method.</param>
        /// <param name="__state">Per-call state previously stored in Prefix.</param>
        public static void PostfixVoid(MethodBase __originalMethod, object __instance, object[] __args, object __state)
        {
            FinalizeLog(__originalMethod, __state, null, true);
        }

        /// <summary>
        /// Finish logging of a method return including elapsed time.
        /// </summary>
        /// <param name="m">MethodBase representing the completed method.</param>
        /// <param name="state">Per-call state (Stopwatch) created in Prefix.</param>
        /// <param name="result">Return value of the method, or null for void methods.</param>
        /// <param name="isVoid">True if the target method returns void.</param>
        static void FinalizeLog(MethodBase m, object state, object result, bool isVoid)
        {
            var sw = state as System.Diagnostics.Stopwatch;
            sw?.Stop();
            var ms = sw?.ElapsedMilliseconds ?? -1;

            var name = $"{m.DeclaringType?.FullName}.{m.Name}";
            var resultText = isVoid ? "void" : SafeJson(result);

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"RET from {name}");
            sb.AppendLine($"\tReturn  : {resultText}");
            sb.AppendLine($"\tElapsed : {ms} ms");

            var logged = sb.ToString();
            if (logged.Length > 200)
                Program.Log(logged.Substring(0, 200));
            else
                Program.Log(logged);
        }

        /// <summary>
        /// Safely serialize an object to JSON for logging.
        /// </summary>
        /// <param name="o">Object to serialize to JSON.</param>
        /// <returns>JSON string representation or fallback ToString/null text on error.</returns>
        static string SafeJson(object o)
        {
            try { return System.Text.Json.JsonSerializer.Serialize(o); }
            catch { return o?.ToString() ?? "null"; }
        }
    }
}

/// <summary>
/// Hooks for intercepting and dumping assemblies that are loaded via Assembly.Load.
/// Used to capture and save assemblies that are loaded dynamically at runtime.
/// </summary>
public static class LoadHooks
{
    /// <summary>
    /// Prefix hook that intercepts Assembly.Load calls and saves the raw assembly bytes to disk.
    /// The assembly is saved with a SHA1-based filename to ensure uniqueness and traceability.
    /// </summary>
    /// <param name="rawAssembly">The raw bytes of the assembly being loaded.</param>
    public static void Prefix(byte[] rawAssembly)
    {
        try
        {
            var sha1 = System.Security.Cryptography.SHA1.Create();
            var hashBytes = sha1.ComputeHash(rawAssembly);
            var hash = BitConverter.ToString(hashBytes).Replace("-", "");
            var dest = Path.Combine(AppContext.BaseDirectory, $"loaded_{hash}.dll");

            File.WriteAllBytes(dest, rawAssembly);
            Program.Log($"[AssemblyDump] Saved raw in-memory assembly -> {dest} ({rawAssembly.Length} bytes)");
        }
        catch (Exception ex)
        {
            Program.Log($"[!] [AssemblyDump] Failed to dump raw assembly: {ex.Message}");
        }
    }
}