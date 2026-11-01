param([switch]$SecureBoot,[switch]$Tpm)
$ErrorActionPreference='Stop'
$watch=[Diagnostics.Stopwatch]::StartNew()
$value=@{query_revision=2;attempts=1;timings_ms=@{}}
if($SecureBoot){
    $before=$watch.ElapsedMilliseconds
    $value.secure_boot=Confirm-SecureBootUEFI -ErrorAction Stop
    $value.timings_ms.secure_boot=$watch.ElapsedMilliseconds-$before
}
if($Tpm){
    $devices=@();$ready=$null
    try{
        $before=$watch.ElapsedMilliseconds
        $devices=@(Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop)
        $value.timings_ms.tpm_device=$watch.ElapsedMilliseconds-$before
        if($devices.Count -gt 1){throw 'Ambiguous TPM device response'}
        $value.tpm_present=($devices.Count -eq 1)
        $value.tpm_ready=$false
        if($value.tpm_present){
            # IsReady checks full TPM/system provisioning. Presence, activation
            # and ownership flags alone do not establish readiness. Avoid the
            # broader Get-Tpm inventory and its unrelated status/auth fields.
            $before=$watch.ElapsedMilliseconds
            $ready=Invoke-CimMethod -InputObject $devices[0] -MethodName IsReady -ErrorAction Stop
            $value.timings_ms.tpm_ready=$watch.ElapsedMilliseconds-$before
            if(($ready.ReturnValue -isnot [uint32] -and $ready.ReturnValue -isnot [int]) -or $ready.ReturnValue -ne 0 -or $ready.IsReady -isnot [bool]){
                throw 'TPM readiness provider failed or returned an invalid response'
            }
            $value.tpm_ready=$ready.IsReady
            $value.tpm_readiness_source='Win32_Tpm.IsReady'
            $id=[uint32]$devices[0].ManufacturerId
            $bytes=[byte[]]@((($id -shr 24)-band 255),(($id -shr 16)-band 255),(($id -shr 8)-band 255),($id-band 255))
            $value.tpm_manufacturer=[Text.Encoding]::ASCII.GetString($bytes).TrimEnd([char]0)
        }
    }finally{
        if($ready -is [IDisposable]){$ready.Dispose()}
        foreach($device in $devices){if($device -is [IDisposable]){$device.Dispose()}}
    }
}
$value.guest_elapsed_ms=$watch.ElapsedMilliseconds
$value|ConvertTo-Json -Depth 4 -Compress
