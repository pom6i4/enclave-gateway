using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;

// Keep trust-provider latency in an owned native child, without starting a
// second PowerShell interpreter for a read-only challenge.
internal static class Attestation
{
    private sealed class TrustProbe
    {
        public string Status="",Signer="";
        public long HashMs,SubjectMs,VerifyMs,CloseMs;
    }
    private static int probeSequence;
    private static readonly Dictionary<string, Guid> subjects = new(StringComparer.OrdinalIgnoreCase);
    private static string? ReadLine()
    {
        var line=new System.Text.StringBuilder();int next;
        while((next=Console.In.Read())>=0 && next!='\n')
        {if(line.Length>=1024*1024)throw new InvalidDataException();line.Append((char)next);}
        if(next<0){if(line.Length!=0)throw new InvalidDataException();return null;}
        return line.ToString();
    }
    public static int Serve(int ownerPid)
    {
        using var owner=Process.GetProcessById(ownerPid);
        // Hold the actual owner's process handle, rather than polling a PID
        // which could be reused. A dead worker cannot leave its trust host.
        _=owner.WaitForExitAsync().ContinueWith(_=>Environment.Exit(125),TaskScheduler.Default);
        // Authenticate the configured identities before advertising readiness.
        // Script SIP initialization can be slow; it belongs to service startup,
        // not an unannounced challenge or a cached response to the first nonce.
        var startup=Stopwatch.StartNew();
        string? initial=ReadLine();
        if(initial is null || initial.Length>1024*1024)return 2;
        using(var configuration=JsonDocument.Parse(Convert.FromBase64String(initial)))
        {
            var value=configuration.RootElement;
            string runtime=Path.GetFullPath(value.GetProperty("runtime_path").GetString()!);
            if(!string.Equals(runtime,Path.GetFullPath(Environment.ProcessPath!),StringComparison.OrdinalIgnoreCase))return 2;
            var workerTrust=Check(value.GetProperty("worker_path").GetString()!,out var workerHash,true);
            var runtimeTrust=Check(runtime,out var runtimeHash,true);
            if(workerHash!=value.GetProperty("worker_sha256").GetString() || runtimeHash!=value.GetProperty("runtime_sha256").GetString())return 2;
            if(value.GetProperty("require_signed").GetBoolean() && (workerTrust.Status!="Valid" || runtimeTrust.Status!="Valid"))return 2;
        }
        Console.WriteLine(JsonSerializer.Serialize(new {ready=1,initialization_ms=startup.ElapsedMilliseconds}));Console.Out.Flush();
        while(true)
        {
            string? line=ReadLine();if(line is null)return 0;
            try
            {
                using var request=JsonDocument.Parse(Convert.FromBase64String(line));
                Console.WriteLine(JsonSerializer.Serialize(Request(request.RootElement,true)));
            }
            catch(Exception){Console.WriteLine("{\"ExitCode\":1,\"Stdout\":\"\",\"Stderr\":\"Native trust unavailable\"}");}
            Console.Out.Flush();
        }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FileInfo
    {
        public uint Size;
        [MarshalAs(UnmanagedType.LPWStr)] public string Path;
        public IntPtr Handle;
        public IntPtr KnownSubject;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint Size;
        public IntPtr PolicyCallback, SipClient;
        public uint UiChoice, RevocationChecks, UnionChoice;
        public IntPtr File;
        public uint StateAction;
        public IntPtr StateData, Url;
        public uint ProviderFlags, UiContext;
        public IntPtr SignatureSettings;
    }
    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint signer, bool counterSigner, uint counterIndex);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateContextProperty(IntPtr context, uint property, byte[] output, ref uint size);
    [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptSIPRetrieveSubjectGuid(string path, IntPtr file, out Guid subject);
    [StructLayout(LayoutKind.Sequential)]
    private struct SignerPrefix
    {
        public uint Size;
        public System.Runtime.InteropServices.ComTypes.FILETIME VerifyAsOf;
        public uint CertificateCount;
        public IntPtr Certificates;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct CertificatePrefix { public uint Size; public IntPtr Context; }

    private static TrustProbe Check(string path, out string hash, bool rememberSubject=false, bool cacheOnly=false)
    {
        var timing=Stopwatch.StartNew();
        // Deny writes and replacement throughout hashing and provider access.
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        hash = Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant();
        file.Position = 0;
        long hashMs=timing.ElapsedMilliseconds;
        // Discover the OS-selected file-format provider during initialization.
        // Reusing its identity avoids rediscovering every registered SIP for
        // each nonce; hashes, signatures and certificate policy remain fresh.
        if(!subjects.TryGetValue(path,out var subject))
        {
            if(!CryptSIPRetrieveSubjectGuid(path,file.SafeFileHandle.DangerousGetHandle(),out subject))
                return new TrustProbe {Status=$"SIP:{Marshal.GetLastWin32Error():x8}",HashMs=hashMs,SubjectMs=timing.ElapsedMilliseconds-hashMs};
            if(rememberSubject && subjects.Count<2)subjects[path]=subject;
        }
        file.Position=0;
        long subjectMs=timing.ElapsedMilliseconds-hashMs;
        IntPtr subjectPointer=Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        Marshal.StructureToPtr(subject,subjectPointer,false);
        var info = new FileInfo { Size = (uint)Marshal.SizeOf<FileInfo>(), Path = path,
                                  Handle = file.SafeFileHandle.DangerousGetHandle(), KnownSubject=subjectPointer };
        IntPtr pointer = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
        Marshal.StructureToPtr(info, pointer, false);
        var data = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), UiChoice = 2,
                                   UnionChoice = 1, File = pointer, StateAction = 1,
                                   ProviderFlags=0x80u | (cacheOnly?0x1000u:0u) };
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        var probe=new TrustProbe {HashMs=hashMs,SubjectMs=subjectMs};
        try
        {
            // Require chain revocation excluding the trusted root. Startup may
            // retrieve revocation material; nonce checks use only fresh OS
            // cache entries. Missing/expired revocation data fails closed.
            timing.Restart();
            int code = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            probe.VerifyMs=timing.ElapsedMilliseconds;
            if (code != 0) {probe.Status=$"WinTrust:{unchecked((uint)code):x8}";return probe;}
            // Read the signer selected by the trust provider, including script
            // SIPs. Parsing a PE-only certificate container misses signed PS1.
            var provider = WTHelperProvDataFromStateData(data.StateData);
            if (provider == IntPtr.Zero) throw new InvalidDataException();
            var signerPointer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
            if (signerPointer == IntPtr.Zero) throw new InvalidDataException();
            var signer = Marshal.PtrToStructure<SignerPrefix>(signerPointer);
            if (signer.CertificateCount == 0 || signer.Certificates == IntPtr.Zero) throw new InvalidDataException();
            var certificate = Marshal.PtrToStructure<CertificatePrefix>(signer.Certificates);
            // WinTrust can honor a user's soft-fail offline publishing policy.
            // Independently require a current code-signing chain with no
            // ignored errors, including unavailable revocation information.
            using var leaf=new X509Certificate2(certificate.Context);
            using var chain=new X509Chain();
            chain.ChainPolicy.RevocationMode=cacheOnly?X509RevocationMode.Offline:X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag=X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags=X509VerificationFlags.NoFlag;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.3"));
            // Supply the provider-selected intermediates without promoting
            // them to trust anchors or relying on another AIA download.
            if(signer.CertificateCount>64 || certificate.Size<Marshal.SizeOf<CertificatePrefix>() || certificate.Size>4096)
                throw new InvalidDataException();
            try
            {
                for(int index=1;index<signer.CertificateCount;index++)
                {
                    var item=Marshal.PtrToStructure<CertificatePrefix>(IntPtr.Add(signer.Certificates,checked(index*(int)certificate.Size)));
                    chain.ChainPolicy.ExtraStore.Add(new X509Certificate2(item.Context));
                }
                if(!chain.Build(leaf)){probe.Status="Chain:revocation-or-policy";return probe;}
            }
            finally{foreach(var item in chain.ChainPolicy.ExtraStore)item.Dispose();}
            var thumbprint = new byte[20]; uint size = (uint)thumbprint.Length;
            if (!CertGetCertificateContextProperty(certificate.Context, 3, thumbprint, ref size) || size != 20)
                throw new InvalidDataException();
            probe.Status="Valid";probe.Signer=Convert.ToHexString(thumbprint);return probe;
        }
        finally
        {
            data.StateAction = 2;
            timing.Restart();
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            probe.CloseMs=timing.ElapsedMilliseconds;
            Marshal.DestroyStructure<FileInfo>(pointer);
            Marshal.FreeHGlobal(pointer);
            Marshal.FreeHGlobal(subjectPointer);
        }
    }

    public static object Request(JsonElement request,bool cacheOnly=false)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var watch = Stopwatch.StartNew();
        var evidence = JsonNode.Parse(request.GetProperty("evidence").GetRawText())!.AsObject();
        string worker = Path.GetFullPath(request.GetProperty("worker_path").GetString()!);
        string runtime = Path.GetFullPath(request.GetProperty("runtime_path").GetString()!);
        if (!request.GetProperty("process_isolation").GetBoolean() ||
            !string.Equals(runtime, Path.GetFullPath(Environment.ProcessPath!), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Runtime identity mismatch");
        var signer = Check(worker, out var workerHash,cacheOnly:cacheOnly);
        evidence["current_sha256"] = workerHash;
        evidence["signature_status"] = signer.Status;
        evidence["signer"] = signer.Signer;
        evidence["worker_hash_ms"]=signer.HashMs;
        evidence["worker_subject_ms"]=signer.SubjectMs;
        evidence["worker_verify_ms"]=signer.VerifyMs;
        evidence["worker_close_ms"]=signer.CloseMs;
        long workerMs = watch.ElapsedMilliseconds;
        signer = Check(runtime, out var runtimeHash,cacheOnly:cacheOnly);
        evidence["runtime_current_sha256"] = runtimeHash;
        evidence["runtime_signature_status"] = signer.Status;
        evidence["runtime_signer"] = signer.Signer;
        evidence["runtime_hash_ms"]=signer.HashMs;
        evidence["runtime_subject_ms"]=signer.SubjectMs;
        evidence["runtime_verify_ms"]=signer.VerifyMs;
        evidence["runtime_close_ms"]=signer.CloseMs;
        evidence["trust_probe"] = "native-winverifytrust";
        evidence["trust_policy"]=cacheOnly?"cache-only-chain-revocation-excluding-root":"online-chain-revocation-excluding-root";
        evidence["trust_host_pid"] = Environment.ProcessId;
        evidence["trust_probe_sequence"] = Interlocked.Increment(ref probeSequence);
        evidence["trust_probe_ms"] = watch.ElapsedMilliseconds;
        evidence["worker_trust_ms"] = workerMs;
        return new { ExitCode = 0, Stdout = evidence.ToJsonString(), Stderr = "" };
    }
}
