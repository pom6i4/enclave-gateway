"""Windows-local deletion of a retired endpoint, validated on the same handle."""

# Appliance maintenance uses this helper outside the Bastion request path.
# Framework Add-Type does not require a .NET SDK.
LOCAL_STREAM_PRUNER = r'''
if(-not ('EnclaveGateway.LocalStreamPruner' -as [type])){
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace EnclaveGateway {
 public static class LocalStreamPruner {
  [StructLayout(LayoutKind.Sequential)] struct Information {
   public uint Attributes;
   public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
   public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [StructLayout(LayoutKind.Sequential)] struct Disposition {
   [MarshalAs(UnmanagedType.Bool)] public bool Delete;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
   IntPtr security, uint creation, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool GetFileInformationByHandle(SafeFileHandle file, out Information info);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool SetFileInformationByHandle(SafeFileHandle file, int kind,
   ref Disposition disposition, uint size);
  public static bool Delete(string path, bool emptyOnly) {
   return DeleteCore(path, emptyOnly, 0);
  }
  public static bool DeleteZero(string path, uint maxBytes) {
   return DeleteCore(path, true, maxBytes);
  }
  static bool DeleteCore(string path, bool emptyOnly, uint maxBytes) {
   // DELETE + GENERIC_READ; exclusive sharing blocks writers, rename and
   // replacement. OPEN_REPARSE_POINT lets the handle check reject links.
   using(var file=CreateFileW(path,0x80010000,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero)) {
    if(file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    Information info;
    if(!GetFileInformationByHandle(file,out info))
     throw new Win32Exception(Marshal.GetLastWin32Error());
    if((info.Attributes & (0x10 | 0x400))!=0 || info.Links!=1) return false;
    if(emptyOnly && (info.SizeHigh!=0 || info.SizeLow>maxBytes)) return false;
    if(emptyOnly && info.SizeLow!=0) {
     using(var stream=new FileStream(file,FileAccess.Read)) {
      var buffer=new byte[65536];
      long total=0;
      int count;
      while((count=stream.Read(buffer,0,buffer.Length))!=0) {
       total+=count;
       for(int i=0;i<count;i++) if(buffer[i]!=0) return false;
      }
      return total==info.SizeLow && MarkDelete(file);
     }
    }
    return MarkDelete(file);
   }
  }
  static bool MarkDelete(SafeFileHandle file) {
   var disposition=new Disposition {Delete=true};
   if(!SetFileInformationByHandle(file,4,ref disposition,4))
    throw new Win32Exception(Marshal.GetLastWin32Error());
   return true;
  }
 }
}
'@
}
'''
