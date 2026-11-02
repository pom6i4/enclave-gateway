using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

internal static class OwnedJob
{
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits { public long ProcessTime,JobTime; public uint Flags; public UIntPtr MinWorkingSet,MaxWorkingSet; public uint ActiveProcesses; public UIntPtr Affinity; public uint Priority,Scheduling; }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong ReadCount,WriteCount,OtherCount,ReadBytes,WriteBytes,OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup { public uint Size; public string? Reserved,Desktop,Title; public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags; public ushort Show,ReservedBytes; public IntPtr ReservedData,Input,Output,Error; }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process,Thread; public uint Pid,Tid; }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateJobObjectW(IntPtr security,string? name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(SafeFileHandle job,int info,ref ExtendedLimits limits,uint size);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string? directory,ref Startup startup,out ProcessInfo process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(SafeFileHandle job,IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr process,out uint exit);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint exit);
    [DllImport("kernel32.dll")] static extern bool TerminateJobObject(SafeFileHandle job,uint exit);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int value);

    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LogonUserW(string user,string domain,string password,int type,int provider,out SafeFileHandle token);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUserW(SafeFileHandle token,string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string? directory,ref Startup startup,out ProcessInfo process);
    [DllImport("userenv.dll",SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr environment,SafeFileHandle token,bool inherit);
    [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct ProfileInfo {public int Size,Flags;public string? UserName,ProfilePath,DefaultPath,ServerName,PolicyPath;public IntPtr Profile;}
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LoadUserProfileW(SafeFileHandle token,ref ProfileInfo profile);
    [DllImport("userenv.dll",SetLastError=true)] static extern bool UnloadUserProfile(SafeFileHandle token,IntPtr profile);
    internal static int RunAs(JsonElement value)
    {
        if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if(!LogonUserW(value.GetProperty("username").GetString()!,value.GetProperty("domain").GetString()!,value.GetProperty("password").GetString()!,4,0,out var token)) throw new Win32Exception();
        using(token)
        {
            using var identity=new System.Security.Principal.WindowsIdentity(token.DangerousGetHandle());
            if(identity.User?.Value!=value.GetProperty("expected_sid").GetString()) throw new System.Security.SecurityException("Logon SID mismatch");
            if(identity.Groups is null || identity.Groups.Any(group=>OperatingSystem.IsWindows() && group.Value=="S-1-5-32-544") || identity.User?.Value is "S-1-5-18" or "S-1-5-19" or "S-1-5-20")
                throw new System.Security.SecurityException("Backend requires a dedicated standard account");
            var profile=new ProfileInfo {Size=Marshal.SizeOf<ProfileInfo>(),Flags=1,UserName=value.GetProperty("username").GetString()};
            if(!LoadUserProfileW(token,ref profile)) throw new Win32Exception();
            try
            {
                if(!CreateEnvironmentBlock(out var environment,token,false)) throw new Win32Exception();
                try
                {
                    if(!value.TryGetProperty("environment",out var configured)) return RunCore(value,token,environment);
                    var block=ConfiguredEnvironment(environment,configured);
                    var pointer=Marshal.StringToHGlobalUni(block);
                    try {return RunCore(value,token,pointer);}
                    finally
                    {
                        for(int i=0;i<block.Length;i++) Marshal.WriteInt16(pointer,i*2,0);
                        Marshal.FreeHGlobal(pointer);
                    }
                }
                finally {DestroyEnvironmentBlock(environment);}
            }
            finally {UnloadUserProfile(token,profile.Profile);}
        }
    }
    static string ConfiguredEnvironment(IntPtr profile,JsonElement configured)
    {
        if(configured.ValueKind!=JsonValueKind.Object) throw new IOException("Invalid configured environment");
        var values=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        int offset=0;
        while(Marshal.ReadInt16(profile,offset)!=0)
        {
            string entry=Marshal.PtrToStringUni(IntPtr.Add(profile,offset))!;
            int separator=entry.IndexOf('=',entry.StartsWith('=')?1:0);
            if(separator<1) throw new IOException("Invalid profile environment");
            values[entry[..separator]]=entry[(separator+1)..];
            offset=checked(offset+(entry.Length+1)*2);
            if(offset>2*1024*1024) throw new IOException("Profile environment limit exceeded");
        }
        var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var property in configured.EnumerateObject())
        {
            string name=property.Name;
            if(names.Count>=128 || name.Length is <1 or >256 || name.IndexOfAny(new[]{'\0','='})>=0 || !names.Add(name) || property.Value.ValueKind!=JsonValueKind.String)
                throw new IOException("Invalid configured environment entry");
            string content=property.Value.GetString()!;
            if(content.Length>32767 || content.Contains('\0')) throw new IOException("Invalid configured environment value");
            values[name]=content;
        }
        string block=string.Join('\0',values.Select(pair=>pair.Key+"="+pair.Value))+"\0\0";
        if(block.Length>1024*1024) throw new IOException("Configured environment limit exceeded");
        return block;
    }
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {public int Length;public IntPtr Descriptor;public int Inherit;}
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out SafeFileHandle read,out SafeFileHandle write,ref SecurityAttributes attributes,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(SafeFileHandle handle,uint mask,uint flags);
    static string Quote(string value)
    {
        if(value.Contains('\0')) throw new IOException("Invalid argument");
        if(value.Length>0 && !value.Any(c=>char.IsWhiteSpace(c) || c=='\"')) return value;
        var output=new StringBuilder("\""); int slashes=0;
        foreach(char c in value) { if(c=='\\') {slashes++; continue;} if(c=='"') {output.Append('\\',slashes*2+1);output.Append(c);} else {output.Append('\\',slashes);output.Append(c);} slashes=0; }
        output.Append('\\',slashes*2);output.Append('"');return output.ToString();
    }
    internal static int Run(JsonElement value)=>RunCore(value,null,IntPtr.Zero);
    static int RunCore(JsonElement value,SafeFileHandle? token,IntPtr environment)
    {
        if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        string[] arguments=value.GetProperty("command").EnumerateArray().Select(v=>v.GetString()!).ToArray();
        int timeout=value.TryGetProperty("timeout_ms",out var duration)?duration.GetInt32():86400000;
        if(arguments.Length==0 || !Path.IsPathFullyQualified(arguments[0]) || timeout<1 || timeout>86400000) throw new IOException("Invalid command");
        string? cancelPath=Cancellation.Token(value);
        if(cancelPath is not null && Cancellation.Requested(cancelPath)) {Cancellation.Clear(cancelPath);return 125;}
        using var job=CreateJobObjectW(IntPtr.Zero,null);
        var limits=new ExtendedLimits {Basic=new BasicLimits {Flags=0x2000}};
        if(job.IsInvalid || !SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf<ExtendedLimits>())) throw new Win32Exception();
        var startup=new Startup {Size=(uint)Marshal.SizeOf<Startup>(),Flags=0x100,Input=GetStdHandle(-10),Output=GetStdHandle(-11),Error=GetStdHandle(-12)};
        SafeFileHandle? inputRead=null,inputWrite=null;
        byte[]? input=null;
        if(value.TryGetProperty("stdin_b64",out var stdin))
        {
            input=Convert.FromBase64String(stdin.GetString()!);
            if(input.Length>8*1024*1024) throw new IOException("Input limit exceeded");
            var security=new SecurityAttributes {Length=Marshal.SizeOf<SecurityAttributes>(),Inherit=1};
            if(!CreatePipe(out inputRead,out inputWrite,ref security,65536)) throw new Win32Exception();
            if(!SetHandleInformation(inputWrite,1,0)) {inputRead.Dispose();inputWrite.Dispose();throw new Win32Exception();}
            startup.Input=inputRead.DangerousGetHandle();
        }
        var command=new StringBuilder(string.Join(' ',arguments.Select(Quote)));
        ProcessInfo process;
        bool created=token is null
            ? CreateProcessW(arguments[0],command,IntPtr.Zero,IntPtr.Zero,true,0x08000004,environment,null,ref startup,out process)
            : CreateProcessAsUserW(token,arguments[0],command,IntPtr.Zero,IntPtr.Zero,true,0x08000404,environment,null,ref startup,out process);
        inputRead?.Dispose();
        if(!created) {inputWrite?.Dispose();throw new Win32Exception();}
        try
        {
            if(!AssignProcessToJobObject(job,process.Process)) {TerminateProcess(process.Process,125);throw new Win32Exception();}
            if(ResumeThread(process.Thread)==0xffffffff) {TerminateJobObject(job,125);throw new Win32Exception();}
            Task? inputTask=null;
            if(inputWrite is not null)
            {
                var writer=inputWrite;var bytes=input!;
                inputTask=Task.Run(()=>{try {using var stream=new FileStream(writer,FileAccess.Write);stream.Write(bytes);stream.Flush();} finally {System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);}});
            }
            var timer=System.Diagnostics.Stopwatch.StartNew();
            uint waited;
            do
            {
                if(cancelPath is not null && Cancellation.Requested(cancelPath)) {TerminateJobObject(job,125);WaitForSingleObject(process.Process,5000);return 125;}
                waited=WaitForSingleObject(process.Process,(uint)Math.Min(100,Math.Max(1,timeout-timer.ElapsedMilliseconds)));
            } while(waited==258 && timer.ElapsedMilliseconds<timeout);
            if(waited==258) {TerminateJobObject(job,124);WaitForSingleObject(process.Process,5000);return 124;}
            if(inputTask is not null) {try {if(!inputTask.Wait(1000)) return 125;} catch {return 125;}}
            if(waited!=0 || !GetExitCodeProcess(process.Process,out uint exit)) {TerminateJobObject(job,125);return 125;}
            // Normal completion also closes the job, terminating background descendants.
            return unchecked((int)exit);
        }
        finally { if(cancelPath is not null) {try {Cancellation.Clear(cancelPath);} catch {}} inputWrite?.Dispose(); if(input is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(input);CloseHandle(process.Thread);CloseHandle(process.Process); }
    }
}
