using System.Text.Json;

try
{
    // Redirected protocol streams must not change a shared Windows console's
    // code page. Detect a StreamWriter's UTF-8 preamble at the stream boundary.
    Console.SetIn(new StreamReader(Console.OpenStandardInput(),new System.Text.UTF8Encoding(false,true),true));
    Console.SetOut(new StreamWriter(Console.OpenStandardOutput(),new System.Text.UTF8Encoding(false)){AutoFlush=true});
    if(args.Length==2 && args[0]=="attest-server" && int.TryParse(args[1],out int ownerPid) && ownerPid>0)
        return Attestation.Serve(ownerPid);
    if (args.Length != 1 || (args[0] != "fs" && args[0] != "run" && args[0] != "run-as" && args[0] != "cancel" && args[0] != "attest")) return 2;
    int maximum=args[0]=="run"?12*1024*1024:1024*1024;
    var buffer=new System.Text.StringBuilder();
    if(args[0]=="run-as")
    {
        int next; while((next=Console.In.Read())>=0 && next!='\n') {if(buffer.Length>=maximum)return 2;buffer.Append((char)next);}
    }
    else
    {
        char[] chunk=new char[8192];int count;
        while((count=Console.In.Read(chunk,0,Math.Min(chunk.Length,maximum-buffer.Length+1)))>0) {buffer.Append(chunk,0,count);if(buffer.Length>maximum)return 2;}
    }
    string input=buffer.ToString();
    using var document = JsonDocument.Parse(input);
    if(args[0]=="attest") {Console.WriteLine(JsonSerializer.Serialize(Attestation.Request(document.RootElement)));return 0;}
    if(args[0]=="cancel") {Console.WriteLine(JsonSerializer.Serialize(Cancellation.Request(document.RootElement)));return 0;}
    if(args[0]=="run") return OwnedJob.Run(document.RootElement);
    if(args[0]=="run-as") return OwnedJob.RunAs(document.RootElement);
    Console.WriteLine(JsonSerializer.Serialize(WindowsFiles.Request(document.RootElement)));
    return 0;
}
catch (Exception error)
{
    int code = error is System.ComponentModel.Win32Exception native ? native.NativeErrorCode : error.HResult;
    Console.WriteLine(JsonSerializer.Serialize(new { error = "native_operation_failed", native_code = code }));
    return 1;
}
