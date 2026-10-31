using System.Text.Json;
using System.Text.RegularExpressions;

internal static class Cancellation
{
    internal static string? Token(JsonElement value)
    {
        if(!value.TryGetProperty("cancel_token",out var token)) return null;
        string text=token.GetString()!;
        if(!Regex.IsMatch(text,"^[a-f0-9]{64}$")) throw new IOException("Invalid cancellation token");
        return text;
    }
    static object Operate(string token,string action)
    {
        string root=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if(action=="mkdir") return WindowsFiles.Request(JsonSerializer.SerializeToElement(new {root,action,path="EnclaveGateway/operations"}));
        return WindowsFiles.Request(JsonSerializer.SerializeToElement(new {root,action,path="EnclaveGateway/operations/"+token+".cancel",offset=0,size=1,data=""}));
    }
    internal static bool Requested(string token)
    {
        try {Operate(token,"read");return true;} catch(IOException) {return false;}
    }
    internal static void Clear(string token) {try {Operate(token,"remove");} catch(IOException) {}}
    internal static object Request(JsonElement value)
    {
        string token=Token(value)??throw new IOException("Token required");
        Operate(token,"mkdir");
        try {Operate(token,"write");} catch(IOException) {if(!Requested(token)) throw;}
        return new {cancel_requested=true};
    }
}
