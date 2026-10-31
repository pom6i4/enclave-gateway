using System.Text;

// The helper has no filesystem, shell, network or credential-vault access.
// OpenSSH receives one UTF-8 line through the inherited standard output pipe.
byte[]? bytes = null;
try
{
    if (args.Length > 1)
        return 2;
    string? encoded = Environment.GetEnvironmentVariable("EGW_ASKPASS_B64");
    if (string.IsNullOrEmpty(encoded) || encoded.Length > 32768)
        return 2;
    bytes = Convert.FromBase64String(encoded);
    string password = new UTF8Encoding(false, true).GetString(bytes);
    if (password.Length == 0 || password.IndexOfAny(new[] { '\0', '\r', '\n' }) >= 0)
        return 2;
    Console.OutputEncoding = new UTF8Encoding(false, true);
    Console.WriteLine(password);
    return 0;
}
catch (Exception error) when (error is FormatException or DecoderFallbackException or IOException)
{
    // Never include the input, exception text or credential in diagnostics.
    return 2;
}
finally
{
    if (bytes != null)
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
}
