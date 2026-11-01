// Disposable Windows-only CA, CRL, OCSP and legacy Authenticode timestamp lab.
using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

if (!OperatingSystem.IsWindows() || args.Length!=1) return 2;
string workspace=Path.GetFullPath(args[0]);
if(Directory.Exists(workspace))throw new IOException("Use a new PKI directory");
Directory.CreateDirectory(workspace);
using var lab=new PkiLab(workspace);
try
{
    lab.Initialize();
    Console.WriteLine(JsonSerializer.Serialize(lab.Description()));Console.Out.Flush();
    while(Console.ReadLine() is string command)
    {
        if(command=="stop")break;
        Console.WriteLine(JsonSerializer.Serialize(lab.Status()));Console.Out.Flush();
    }
    return 0;
}
catch(Exception error)
{
    File.WriteAllText(Path.Combine(workspace,"failure.json"),JsonSerializer.Serialize(new {error=error.GetType().Name}));
    throw;
}

sealed class PkiLab:IDisposable
{
    readonly string workspace;
    readonly string prefix="EGW-PKI-"+Guid.NewGuid().ToString("N");
    readonly List<X509Certificate2> certificates=new();
    readonly List<CngKey> keys=new();
    readonly ConcurrentDictionary<string,int> requests=new();
    readonly Dictionary<string,byte[]> crls=new();
    readonly Dictionary<string,X509Certificate2> leaves=new();
    readonly TcpListener listener=new(IPAddress.Loopback,0);
    readonly CancellationTokenSource cancellation=new();
    readonly DateTimeOffset now=DateTimeOffset.UtcNow;
    X509Certificate2? root,tsa;
    Task? server;
    string origin="";
    DateTimeOffset cacheExpiry;
    int crlNumber;
    public PkiLab(string path){workspace=path;}
    X509Certificate2 Issue(string name,string? eku=null,string? crl=null,bool ocsp=false,DateTimeOffset? expiry=null)
    {
        var parameters=new CngKeyCreationParameters{Provider=CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy=CngExportPolicies.None,KeyCreationOptions=CngKeyCreationOptions.MachineKey};
        parameters.Parameters.Add(new CngProperty("Length",BitConverter.GetBytes(2048),CngPropertyOptions.None));
        var key=CngKey.Create(CngAlgorithm.Rsa,prefix+"-"+name,parameters);keys.Add(key);
        using var rsa=new RSACng(key);
        var request=new CertificateRequest("CN="+prefix+" "+name,rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        bool ca=eku is null;
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca,false,0,true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(ca?X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign:X509KeyUsageFlags.DigitalSignature,true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey,false));
        if(eku is not null){var oids=new OidCollection();oids.Add(new Oid(eku));request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(oids,true));}
        if(crl is not null)
        {
            var writer=new AsnWriter(AsnEncodingRules.DER);writer.PushSequence();writer.PushSequence();
            var tag=new Asn1Tag(TagClass.ContextSpecific,0,true);writer.PushSequence(tag);writer.PushSequence(tag);
            writer.WriteCharacterString(UniversalTagNumber.IA5String,origin+"/"+crl+".crl",new Asn1Tag(TagClass.ContextSpecific,6));
            writer.PopSequence(tag);writer.PopSequence(tag);writer.PopSequence();writer.PopSequence();
            request.CertificateExtensions.Add(new X509Extension("2.5.29.31",writer.Encode(),false));
        }
        if(ocsp)
        {
            var writer=new AsnWriter(AsnEncodingRules.DER);writer.PushSequence();writer.PushSequence();
            writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1");
            writer.WriteCharacterString(UniversalTagNumber.IA5String,origin+"/ocsp/"+name,new Asn1Tag(TagClass.ContextSpecific,6));
            writer.PopSequence();writer.PopSequence();request.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.1",writer.Encode(),false));
        }
        X509Certificate2 certificate;
        if(ca)certificate=request.CreateSelfSigned(now.AddMinutes(-10),now.AddHours(3));
        else
        {
            using var issued=request.Create(root!,now.AddMinutes(-5),expiry??now.AddHours(2),RandomNumberGenerator.GetBytes(16));
            certificate=issued.CopyWithPrivateKey(rsa);
        }
        certificates.Add(certificate);
        using var store=new X509Store(StoreName.My,StoreLocation.LocalMachine);store.Open(OpenFlags.ReadWrite);store.Add(certificate);
        File.WriteAllBytes(Path.Combine(workspace,name+".cer"),certificate.RawData);
        return certificate;
    }
    byte[] Crl(string name,X509Certificate2? revoked,DateTimeOffset next)
    {
        var builder=new CertificateRevocationListBuilder();if(revoked is not null)builder.AddEntry(revoked,now.AddMinutes(-3),X509RevocationReason.KeyCompromise);
        byte[] initial=builder.Build(root!,++crlNumber,next,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1,now.AddMinutes(-2));
        // Partition the issuer's revocation population by advertised URL.
        // A fresh CRL from another case must not satisfy a stale/cache case.
        var idp=new AsnWriter(AsnEncodingRules.DER);var zero=new Asn1Tag(TagClass.ContextSpecific,0,true);
        idp.PushSequence();idp.PushSequence(zero);idp.PushSequence(zero);
        idp.WriteCharacterString(UniversalTagNumber.IA5String,origin+"/"+name+".crl",new Asn1Tag(TagClass.ContextSpecific,6));
        idp.PopSequence(zero);idp.PopSequence(zero);idp.PopSequence();
        var original=new AsnReader(initial,AsnEncodingRules.DER).ReadSequence();var source=original.ReadSequence();
        var tbs=new AsnWriter(AsnEncodingRules.DER);tbs.PushSequence();bool extensions=false;
        while(source.HasData)
        {
            if(!source.PeekTag().HasSameClassAndValue(zero)){tbs.WriteEncodedValue(source.ReadEncodedValue().Span);continue;}
            var values=source.ReadSequence(zero).ReadSequence();tbs.PushSequence(zero);tbs.PushSequence();
            while(values.HasData)tbs.WriteEncodedValue(values.ReadEncodedValue().Span);
            tbs.PushSequence();tbs.WriteObjectIdentifier("2.5.29.28");tbs.WriteBoolean(true);tbs.WriteOctetString(idp.Encode());tbs.PopSequence();
            tbs.PopSequence();tbs.PopSequence(zero);extensions=true;
        }
        if(!extensions)throw new InvalidDataException("CRL extensions missing");
        tbs.PopSequence();byte[] encoded=tbs.Encode();using var rsa=root!.GetRSAPrivateKey()!;
        var result=new AsnWriter(AsnEncodingRules.DER);result.PushSequence();result.WriteEncodedValue(encoded);
        result.WriteEncodedValue(original.ReadEncodedValue().Span);result.WriteBitString(rsa.SignData(encoded,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1));result.PopSequence();
        return result.Encode();
    }
    public void Initialize()
    {
        listener.Start();origin="http://127.0.0.1:"+((IPEndPoint)listener.LocalEndpoint).Port;
        root=Issue("root");using(var store=new X509Store(StoreName.Root,StoreLocation.LocalMachine)){store.Open(OpenFlags.ReadWrite);store.Add(root);}
        foreach(string name in new[]{"good","revoked","stale","cache","rotation","expired"})
            leaves.Add(name,Issue(name,"1.3.6.1.5.5.7.3.3",name,expiry:name=="expired"?now.AddMinutes(5):null));
        leaves.Add("ocsp-good",Issue("ocsp-good","1.3.6.1.5.5.7.3.3",ocsp:true));
        leaves.Add("ocsp-revoked",Issue("ocsp-revoked","1.3.6.1.5.5.7.3.3",ocsp:true));
        tsa=Issue("tsa","1.3.6.1.5.5.7.3.8","good");
        cacheExpiry=now.AddMinutes(5);
        foreach(string name in new[]{"good","revoked","stale","cache","rotation","expired"})
        {
            crls.Add(name,Crl(name,name=="revoked"?leaves["revoked"]:null,name=="stale"?now.AddMinutes(-1):name=="cache"?cacheExpiry:now.AddHours(1)));
            File.WriteAllBytes(Path.Combine(workspace,name+".crl"),crls[name]);
        }
        server=Task.Run(Serve);
    }
    public object Description()=>new{status="ready",origin,root=root!.Thumbprint,tsa=tsa!.Thumbprint,
        certificates=leaves.ToDictionary(x=>x.Key,x=>x.Value.Thumbprint),cache_expiry=cacheExpiry,signer_expiry=leaves["expired"].NotAfter.ToUniversalTime(),crl_scope="critical-issuing-distribution-points",private_keys="nonexportable-disposable-machine-keys"};
    public object Status()=>new{status="serving",requests=requests.ToDictionary(x=>x.Key,x=>x.Value)};
    async Task Serve()
    {
        while(!cancellation.IsCancellationRequested)
        {
            TcpClient client;
            try{client=await listener.AcceptTcpClientAsync(cancellation.Token);}catch(OperationCanceledException){break;}
            _=Task.Run(()=>Handle(client));
        }
    }
    async Task Handle(TcpClient client)
    {
        using(client)
        {
            client.ReceiveTimeout=15000;client.SendTimeout=15000;
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));var token=timeout.Token;
            var stream=client.GetStream();var header=new List<byte>();byte[] one=new byte[1];
            try
            {
                while(header.Count<16384)
                {
                    if(await stream.ReadAsync(one,token)!=1)return;header.Add(one[0]);
                    int n=header.Count;if(n>=4 && header[n-4]==13 && header[n-3]==10 && header[n-2]==13 && header[n-1]==10)break;
                }
                string[] lines=Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");var first=lines[0].Split(' ');
                if(first.Length!=3)return;
                int length=0;
                foreach(string line in lines.Skip(1))if(line.StartsWith("Content-Length:",StringComparison.OrdinalIgnoreCase))length=int.Parse(line.Split(':',2)[1]);
                if(length<0 || length>1024*1024)return;
                byte[] body=new byte[length];await stream.ReadExactlyAsync(body,token);
                string path=new Uri(origin+first[1]).AbsolutePath;
                byte[] response;string type="application/octet-stream";
                if(path=="/timestamp")
                {
                    requests.AddOrUpdate("timestamp",1,(_,n)=>n+1);response=Timestamp(body);
                }
                else if(path.StartsWith("/ocsp/",StringComparison.Ordinal))
                {
                    string name=path.Split('/')[2];
                    requests.AddOrUpdate(name,1,(_,n)=>n+1);
                    if(first[0]=="GET")body=Convert.FromBase64String(Uri.UnescapeDataString(string.Join('/',path.Split('/').Skip(3))));
                    response=Ocsp(body,name=="ocsp-revoked");type="application/ocsp-response";
                }
                else
                {
                    string name=Path.GetFileNameWithoutExtension(path);requests.AddOrUpdate(name,1,(_,n)=>n+1);
                    response=crls[name];type="application/pkix-crl";
                }
                byte[] prefixBytes=Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: {type}\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(prefixBytes,token);await stream.WriteAsync(response,token);
            }
            catch(Exception error){File.AppendAllText(Path.Combine(workspace,"http-errors.log"),error.GetType().Name+":"+error.StackTrace+"\n");}
        }
    }
    byte[] Timestamp(byte[] body)
    {
        // Windows publishers can terminate the legacy base64 transport with
        // a NUL; the request remains bounded and must decode to strict DER.
        byte[] der=body.Length>0 && body[0]==0x30?body:Convert.FromBase64String(Encoding.ASCII.GetString(body).TrimEnd('\0','\r','\n',' '));
        var seq=new AsnReader(der,AsnEncodingRules.DER).ReadSequence();
        if(seq.ReadObjectIdentifier()!="1.3.6.1.4.1.311.3.2.1")throw new InvalidDataException();
        var content=seq.ReadSequence();if(content.ReadObjectIdentifier()!="1.2.840.113549.1.7.1")throw new InvalidDataException();
        byte[] signature=content.ReadSequence(new Asn1Tag(TagClass.ContextSpecific,0,true)).ReadOctetString();
        var cms=new SignedCms(new ContentInfo(signature),false);var signer=new CmsSigner(tsa!){DigestAlgorithm=new Oid("2.16.840.1.101.3.4.2.1"),IncludeOption=X509IncludeOption.WholeChain};
        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));cms.ComputeSignature(signer);
        return Encoding.ASCII.GetBytes(Convert.ToBase64String(cms.Encode()));
    }
    byte[] Ocsp(byte[] body,bool revoked)
    {
        var tbs=new AsnReader(body,AsnEncodingRules.DER).ReadSequence().ReadSequence();
        // CryptoAPI requests use the default version with an unsigned request.
        var request=tbs.ReadSequence().ReadSequence();byte[] certId=request.ReadEncodedValue().ToArray();
        var data=new AsnWriter(AsnEncodingRules.DER);data.PushSequence();
        var tag=new Asn1Tag(TagClass.ContextSpecific,1,true);data.PushSequence(tag);data.WriteEncodedValue(root!.SubjectName.RawData);data.PopSequence(tag);
        var instant=DateTimeOffset.UtcNow;data.WriteGeneralizedTime(instant,true);data.PushSequence();data.PushSequence();data.WriteEncodedValue(certId);
        if(revoked){data.PushSequence(tag);data.WriteGeneralizedTime(now.AddMinutes(-1),true);data.PopSequence(tag);}
        else data.WriteNull(new Asn1Tag(TagClass.ContextSpecific,0));
        data.WriteGeneralizedTime(now.AddMinutes(-1),true);
        var explicitZero=new Asn1Tag(TagClass.ContextSpecific,0,true);data.PushSequence(explicitZero);data.WriteGeneralizedTime(now.AddHours(1),true);data.PopSequence(explicitZero);
        data.PopSequence();data.PopSequence();data.PopSequence();byte[] encoded=data.Encode();
        using var rsa=root.GetRSAPrivateKey()!;byte[] signature=rsa.SignData(encoded,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        var basic=new AsnWriter(AsnEncodingRules.DER);basic.PushSequence();basic.WriteEncodedValue(encoded);basic.PushSequence();basic.WriteObjectIdentifier("1.2.840.113549.1.1.11");basic.WriteNull();basic.PopSequence();basic.WriteBitString(signature);
        basic.PushSequence(explicitZero);basic.PushSequence();basic.WriteEncodedValue(root.RawData);basic.PopSequence();basic.PopSequence(explicitZero);basic.PopSequence();
        var response=new AsnWriter(AsnEncodingRules.DER);response.PushSequence();response.WriteEnumeratedValue(ResponseStatus.Successful);response.PushSequence(explicitZero);response.PushSequence();response.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1.1");response.WriteOctetString(basic.Encode());response.PopSequence();response.PopSequence(explicitZero);response.PopSequence();return response.Encode();
    }
    enum ResponseStatus{Successful=0}
    public void Dispose()
    {
        cancellation.Cancel();listener.Stop();try{server?.Wait(TimeSpan.FromSeconds(20));}catch(AggregateException){}
        using(var roots=new X509Store(StoreName.Root,StoreLocation.LocalMachine)){roots.Open(OpenFlags.ReadWrite);if(root is not null)roots.Remove(root);}
        using(var mine=new X509Store(StoreName.My,StoreLocation.LocalMachine)){mine.Open(OpenFlags.ReadWrite);foreach(var certificate in certificates){mine.Remove(certificate);certificate.Dispose();}}
        foreach(var key in keys){try{key.Delete();}finally{key.Dispose();}}
        cancellation.Dispose();File.WriteAllText(Path.Combine(workspace,"cleanup.json"),JsonSerializer.Serialize(new{status="passed",keys="deleted",certificates="removed",listener="stopped"}));
    }
}
