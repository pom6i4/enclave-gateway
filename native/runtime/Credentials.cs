using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

// Credentials arrive on stdin. No generated script, argv password or temporary
// credential file is used. Cross-session access requires the OS-granted token.
internal static class Credentials
{
    [StructLayout(LayoutKind.Sequential)] struct Session { public int Id; public IntPtr Name; public int State; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Credential
    {
        public uint Flags, Type; public string Target; public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME Written;
        public uint BlobSize; public IntPtr Blob; public uint Persist, Attributes;
        public IntPtr Attribute; public string? Alias; public string User;
    }
    [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSEnumerateSessionsW(IntPtr server,int reserved,int version,out IntPtr sessions,out int count);
    [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQueryUserToken(uint session,out SafeAccessTokenHandle token);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CredWriteW(ref Credential credential,uint flags);

    public static object Request(JsonElement value)
    {
        if(!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        string[] fields={"expected_sid","target","username","password"};
        var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(var property in value.EnumerateObject())
            if(!fields.Contains(property.Name) || !seen.Add(property.Name) || property.Value.ValueKind!=JsonValueKind.String) throw new InvalidDataException();
        if(seen.Count!=fields.Length) throw new InvalidDataException();
        string sid=value.GetProperty("expected_sid").GetString()!;
        _=new SecurityIdentifier(sid);
        string target=value.GetProperty("target").GetString()!;
        string user=value.GetProperty("username").GetString()!;
        string password=value.GetProperty("password").GetString()!;
        if(!target.StartsWith("TERMSRV/",StringComparison.Ordinal) || target.Length is <9 or >1024 ||
           target[8..].Any(c=>!(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or ':' or '[' or ']')) ||
           user.Length is <1 or >513 || password.Length is <1 or >1280 ||
           user.Any(char.IsControl) || password.Contains('\0')) throw new InvalidDataException();
        using var current=WindowsIdentity.GetCurrent();
        if(current.User?.Value==sid) {Write(target,user,password);return new {credential_updated=true};}
        if(current.User?.Value!="S-1-5-18") throw new UnauthorizedAccessException();
        if(!WTSEnumerateSessionsW(IntPtr.Zero,0,1,out var sessions,out int count)) throw new Win32Exception();
        SafeAccessTokenHandle? selected=null;
        try
        {
            for(int i=0;i<count;i++)
            {
                var session=Marshal.PtrToStructure<Session>(IntPtr.Add(sessions,i*Marshal.SizeOf<Session>()));
                if(session.State!=0 || !WTSQueryUserToken((uint)session.Id,out var token)) continue;
                using var identity=new WindowsIdentity(token.DangerousGetHandle());
                if(identity.User?.Value!=sid) {token.Dispose();continue;}
                if(selected is not null) {token.Dispose();throw new IOException("Ambiguous interactive session");}
                selected=token;
            }
            if(selected is null) throw new UnauthorizedAccessException();
            WindowsIdentity.RunImpersonated(selected,()=>Write(target,user,password));
            return new {credential_updated=true};
        }
        finally {selected?.Dispose();WTSFreeMemory(sessions);}
    }

    static void Write(string target,string user,string password)
    {
        var blob=Marshal.StringToCoTaskMemUni(password);
        try
        {
            var credential=new Credential {Type=1,Target=target,User=user,BlobSize=checked((uint)password.Length*2),Blob=blob,Persist=2};
            if(!CredWriteW(ref credential,0)) throw new Win32Exception();
        }
        finally {Marshal.ZeroFreeCoTaskMemUnicode(blob);}
    }
}
