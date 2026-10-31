using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

// Every descendant is opened relative to an already opened directory handle.
// Reparse points are opened themselves and rejected, never traversed.
internal sealed class WindowsFiles : IDisposable
{
    const uint Read = 0x80000000, Write = 0x40000000, Sync = 0x100000, Delete = 0x10000;
    const int Chunk = 192 * 1024;
    readonly SafeFileHandle root;
    [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public int Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status; public UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)] struct FileInfo { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written; public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,SafeFileHandle source,IntPtr targetProcess,out SafeFileHandle target,uint access,bool inherit,uint options);
    [DllImport("ntdll.dll")] static extern int NtCreateFile(out SafeFileHandle handle,uint access,ref ObjectAttributes attributes,out IoStatus status,IntPtr allocation,uint fileAttributes,uint share,uint disposition,uint options,IntPtr ea,uint eaLength);
    [DllImport("ntdll.dll")] static extern int NtQueryDirectoryFile(SafeFileHandle handle,IntPtr evt,IntPtr apc,IntPtr context,out IoStatus status,IntPtr buffer,uint length,int infoClass,[MarshalAs(UnmanagedType.U1)]bool single,IntPtr name,[MarshalAs(UnmanagedType.U1)]bool restart);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfo information);
    [DllImport("ntdll.dll")] static extern int NtSetInformationFile(SafeFileHandle handle,out IoStatus status,IntPtr data,uint size,int infoClass);
    [DllImport("ntdll.dll")] static extern uint RtlNtStatusToDosError(int status);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle handle,int type,IntPtr data,uint size);

    static string[] Parts(string path)
    {
        if (path.Length==0) return [];
        var parts=path.Split('/');
        if (parts.Any(p=>p.Length==0 || p is "." or ".." || p.Contains('\\') || p.Contains(':') || p.Contains('\0') || p.EndsWith('.') || p.EndsWith(' ') || Regex.IsMatch(p,@"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$",RegexOptions.IgnoreCase)))
            throw new IOException("Invalid relative path");
        return parts;
    }
    static FileInfo Inspect(SafeFileHandle handle,bool directory)
    {
        if (handle.IsInvalid || !GetFileInformationByHandle(handle,out var info)) throw new Win32Exception();
        if ((info.Attributes & 0x440)!=0 || ((info.Attributes & 0x10)!=0)!=directory || (!directory && info.Links!=1))
            throw new IOException("Links and special files are forbidden");
        return info;
    }
    static SafeFileHandle Open(SafeFileHandle parent,string name,bool directory,uint access,uint disposition=1)
    {
        Parts(name); // callers provide exactly one component
        if (name.Contains('/')) throw new IOException("One component required");
        IntPtr text=Marshal.StringToHGlobalUni(name),unicode=IntPtr.Zero;
        SafeFileHandle? result=null;
        try
        {
            int length=Encoding.Unicode.GetByteCount(name);
            if (length>65532) throw new IOException("Name too long");
            var value=new UnicodeString { Length=(ushort)length,MaximumLength=(ushort)(length+2),Buffer=text };
            unicode=Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>()); Marshal.StructureToPtr(value,unicode,false);
            var attributes=new ObjectAttributes { Length=Marshal.SizeOf<ObjectAttributes>(),RootDirectory=parent.DangerousGetHandle(),ObjectName=unicode,Attributes=0x40 };
            // Allow writes within an opened directory while denying its rename/delete.
            int status=NtCreateFile(out result,access|Sync,ref attributes,out _,IntPtr.Zero,0,directory?3u:1u,disposition,0x200000|0x20|(directory?1u:0x40u),IntPtr.Zero,0);
            if (status<0) throw new IOException("Handle-relative open failed: "+status.ToString("x"));
            Inspect(result,directory); return result;
        }
        catch { result?.Dispose(); throw; }
        finally { Marshal.FreeHGlobal(text); if (unicode!=IntPtr.Zero) Marshal.FreeHGlobal(unicode); }
    }
    public WindowsFiles(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (!Path.IsPathFullyQualified(path)) throw new IOException("Absolute root required");
        string anchor=Path.GetPathRoot(path)!;
        // Device namespaces are not accepted as configured roots.
        if (anchor.StartsWith(@"\\?\") || anchor.StartsWith(@"\\.\")) throw new IOException("Device roots forbidden");
        var current=CreateFileW(anchor,0x81|Sync,7,IntPtr.Zero,3,0x2200000,IntPtr.Zero);
        try
        {
            Inspect(current,true);
            foreach (string part in Parts(path[anchor.Length..].TrimEnd('\\','/').Replace('\\','/')))
            { var next=Open(current,part,true,0x81); current.Dispose(); current=next; }
            root=current;
        }
        catch { current.Dispose(); throw; }
    }
    public void Dispose()=>root.Dispose();
    SafeFileHandle Directory(string path,bool create=false)
    {
        // Open a fresh reference to '.' relative to the retained root handle.
        if(!DuplicateHandle(GetCurrentProcess(),root,GetCurrentProcess(),out var current,0,false,2)) throw new Win32Exception();
        try
        {
            foreach (string part in Parts(path)) { var next=Open(current,part,true,0x81,create?3u:1u); current.Dispose(); current=next; }
            return current;
        }
        catch { current.Dispose(); throw; }
    }
    (SafeFileHandle,string) Parent(string path,bool create=false)
    {
        var parts=Parts(path); if(parts.Length==0) throw new IOException("File required");
        return (Directory(string.Join('/',parts[..^1]),create),parts[^1]);
    }
    List<string> Names(SafeFileHandle directory)
    {
        var names=new List<string>(); IntPtr buffer=Marshal.AllocHGlobal(65536);
        try
        {
            bool restart=true;
            while(true)
            {
                int status=NtQueryDirectoryFile(directory,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out var io,buffer,65536,12,false,IntPtr.Zero,restart); restart=false;
                if(status==unchecked((int)0x80000006)) break;
                if(status<0) throw new IOException("Directory enumeration failed");
                int offset=0,used=checked((int)io.Information.ToUInt64());
                while(offset<used)
                {
                    int next=Marshal.ReadInt32(buffer,offset),length=Marshal.ReadInt32(buffer,offset+8);
                    if(length<0 || offset+12+length>used) throw new IOException("Invalid directory record");
                    string name=Marshal.PtrToStringUni(buffer+offset+12,length/2)!;
                    if(name is not "." and not "..") { Parts(name); names.Add(name); }
                    if(next==0) break;
                    if(next<12 || offset+next>=used) throw new IOException("Invalid directory offset");
                    offset+=next;
                }
                if(names.Count>10000) throw new IOException("Tree exceeds limit");
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return names;
    }
    object[] List(string path,string[] exclude)
    {
        var entries=new List<object>();
        void Walk(string relative)
        {
            using var directory=Directory(relative);
            foreach(string name in Names(directory))
            {
                string child=(relative.Length>0?relative+"/":"")+name;
                bool Excluded(string value,string pattern)=>Regex.IsMatch(value,"^"+Regex.Escape(pattern).Replace("\\*",".*").Replace("\\?",".")+"$");
                if(exclude.Any(pattern=>Excluded(child,pattern) || child.Split('/').Any(part=>Excluded(part,pattern)))) continue;
                // Open without assuming its type, inspect before reading/traversing.
                using var handle=OpenAny(directory,name);
                if(!GetFileInformationByHandle(handle,out var info) || (info.Attributes&0x440)!=0) throw new IOException("Unsafe entry");
                if((info.Attributes&0x10)!=0) { entries.Add(new {path=child,kind="dir"}); Walk(child); }
                else
                {
                    Inspect(handle,false);
                    using var stream=new FileStream(handle,FileAccess.Read);
                    entries.Add(new {path=child,kind="file",size=stream.Length,sha256=Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant()});
                }
                if(entries.Count>10000) throw new IOException("Tree exceeds limit");
            }
        }
        Walk(path); return entries.ToArray();
    }
    static SafeFileHandle OpenAny(SafeFileHandle parent,string name)
    {
        try { return Open(parent,name,false,Read); }
        catch(IOException) { return Open(parent,name,true,0x81); }
    }
    public static object Request(JsonElement value)
    {
        using var fs=new WindowsFiles(value.GetProperty("root").GetString()!);
        string action=value.GetProperty("action").GetString()!,path=value.TryGetProperty("path",out var p)?p.GetString()!:"";
        if(action=="list") return new {entries=fs.List(path,value.TryGetProperty("exclude",out var exclusions)?exclusions.EnumerateArray().Select(v=>v.GetString()!).ToArray():[])};
        if(action=="mkdir") { using var directory=fs.Directory(path,true); return new {ok=true}; }
        var (parent,name)=fs.Parent(path,action=="write");
        using(parent)
        {
            if(action=="read")
            {
                long offset=value.GetProperty("offset").GetInt64(); int size=value.GetProperty("size").GetInt32();
                if(offset<0 || size<1 || size>Chunk) throw new IOException("Invalid geometry");
                using var handle=Open(parent,name,false,Read); using var stream=new FileStream(handle,FileAccess.Read);
                stream.Position=offset; byte[] bytes=new byte[size]; int count=stream.Read(bytes);
                return new {data=Convert.ToBase64String(bytes,0,count)};
            }
            if(action=="write")
            {
                long offset=value.GetProperty("offset").GetInt64(); byte[] bytes=Convert.FromBase64String(value.GetProperty("data").GetString()!);
                if(offset<0 || bytes.Length>Chunk) throw new IOException("Invalid geometry");
                using var handle=Open(parent,name,false,Read|Write,offset==0?2u:1u); using var stream=new FileStream(handle,FileAccess.ReadWrite);
                if(stream.Length!=offset) throw new IOException("Stage offset mismatch");
                stream.Position=offset; stream.Write(bytes); stream.Flush(true);
            }
            else if(action=="commit")
            {
                using var handle=Open(parent,name,false,Read|Delete);
                using(var stream=new FileStream(handle,FileAccess.Read))
                {
                    string actual=Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
                    if(actual!=value.GetProperty("sha256").GetString()) throw new IOException("Digest mismatch");
                    var (targetParent,targetName)=fs.Parent(value.GetProperty("target").GetString()!,true);
                    using(targetParent)
                    {
                        byte[] bytes=Encoding.Unicode.GetBytes(targetName); int head=IntPtr.Size==8?20:12;
                        int size=(IntPtr.Size==8?24:16)+bytes.Length;
                        IntPtr data=Marshal.AllocHGlobal(size);
                        try
                        {
                            for(int i=0;i<size;i++) Marshal.WriteByte(data,i,0);
                            Marshal.WriteInt32(data,1); Marshal.WriteIntPtr(data,IntPtr.Size==8?8:4,targetParent.DangerousGetHandle()); Marshal.WriteInt32(data,head-4,bytes.Length); Marshal.Copy(bytes,0,data+head,bytes.Length);
                            // The Win32 rename wrapper rejects non-null RootDirectory; the NT
                            // operation keeps the destination anchored to the retained handle.
                            int status=NtSetInformationFile(handle,out _,data,(uint)size,10);
                            if(status<0) throw new Win32Exception((int)RtlNtStatusToDosError(status));
                        }
                        finally { Marshal.FreeHGlobal(data); }
                    }
                }
            }
            else if(action=="remove")
            {
                SafeFileHandle handle;
                try { handle=Open(parent,name,false,Delete|0x80); }
                catch(IOException) { return new {ok=true}; }
                using(handle)
                {
                    IntPtr data=Marshal.AllocHGlobal(4);
                    try { Marshal.WriteInt32(data,1); if(!SetFileInformationByHandle(handle,4,data,4)) throw new Win32Exception(); }
                    finally { Marshal.FreeHGlobal(data); }
                }
            }
            else throw new IOException("Unsupported filesystem action");
        }
        return new {ok=true};
    }
}
