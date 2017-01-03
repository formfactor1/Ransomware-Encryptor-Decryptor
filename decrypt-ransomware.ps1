<#
Powershell ransomware decrypter
.Description
This powershell script decrypt files using an X.509 public key certificate
It will decrypt the files that are encrypted by the encryption script. It's designed to decrypt files on the lowest drive letter first. This allows you to control what share is being decrypted.
I recommend only have one drive mapped to ensure only one share is decrypted. I often map a Z: drive to my test share.
.Instructions
You must have a valid cert. Issue this command to see if you have cert we can use. Get-ChildItem Cert:\CurrentUser\My\
Copy the thumbprint to line 17 below. It should be the same thumbprint used in the encryption script
.Notes
Credit to Ryan Ries for developing the decryption and filestream scriptblock.
http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509certificate2.aspx
Written by Nathan Studebaker
#>

#define the cert to use for decryption
$Cert = $(Get-ChildItem Cert:\CurrentUser\My\F09CC285277DBAC041935B8D96ABE2C1BF123C46)

#enumerate drives
$psdrives = get-psdrive | select-object -property Root, DisplayRoot

#find network drives
$netdrives = @($psdrives)."DisplayRoot"

#enumerate network drives
ForEach ($n in $netdrives)
    {
    If ($n)
        {
        #decrypt files and ignore directories
        $FileToDecrypt = get-childitem -path $n -Recurse -force | where-object{!($_.PSIsContainter)} | % {$_.FullName} -ErrorAction SilentlyContinue  
        }
        Else
        {
        Write-Host "File not accessible"
        }
    }

#decryption and filestream function
Function Decrypt-File
{
    Param([Parameter(mandatory=$true)][System.IO.FileInfo]$FileToDecrypt,
          [Parameter(mandatory=$true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
 
    Try { [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Cryptography") }
    Catch { Write-Error "Could not load required assembly."; Return }
     
    $AesProvider                = New-Object System.Security.Cryptography.AesManaged
    $AesProvider.KeySize        = 256
    $AesProvider.BlockSize      = 128
    $AesProvider.Mode           = [System.Security.Cryptography.CipherMode]::CBC
    [Byte[]]$LenKey             = New-Object Byte[] 4
    [Byte[]]$LenIV              = New-Object Byte[] 4
    If($Cert.HasPrivateKey -eq $False -or $Cert.PrivateKey -eq $null)
    {
        Write-Error "The supplied certificate does not contain a private key, or it could not be accessed."
        Return
    }
    Try { $FileStreamReader = New-Object System.IO.FileStream("$($FileToDecrypt.FullName)", [System.IO.FileMode]::Open) }
    Catch
    {
        Write-Error "Unable to open input file for reading."       
        Return
    }  
    $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($LenKey, 0, 3)                            | Out-Null
    $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($LenIV,  0, 3)                            | Out-Null
    [Int]$LKey            = [System.BitConverter]::ToInt32($LenKey, 0)
    [Int]$LIV             = [System.BitConverter]::ToInt32($LenIV,  0)
    [Int]$StartC          = $LKey + $LIV + 8
    [Int]$LenC            = [Int]$FileStreamReader.Length - $StartC
    [Byte[]]$KeyEncrypted = New-Object Byte[] $LKey
    [Byte[]]$IV           = New-Object Byte[] $LIV
    $FileStreamReader.Seek(8, [System.IO.SeekOrigin]::Begin)         | Out-Null
    $FileStreamReader.Read($KeyEncrypted, 0, $LKey)                  | Out-Null
    $FileStreamReader.Seek(8 + $LKey, [System.IO.SeekOrigin]::Begin) | Out-Null
    $FileStreamReader.Read($IV, 0, $LIV)                             | Out-Null
    [Byte[]]$KeyDecrypted = $Cert.PrivateKey.Decrypt($KeyEncrypted, $false)
    $Transform = $AesProvider.CreateDecryptor($KeyDecrypted, $IV)
    Try { $FileStreamWriter = New-Object System.IO.FileStream("$($env:TEMP)\$($FileToDecrypt.Name)", [System.IO.FileMode]::Create) }
    Catch
    {
        Write-Error "Unable to open output file for writing.`n$($_.Message)"
        $FileStreamReader.Close()
        Return
    }
    [Int]$Count  = 0
    [Int]$Offset = 0
    [Int]$BlockSizeBytes = $AesProvider.BlockSize / 8
    [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
    Do
    {
        $Count   = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
        $Offset += $Count
        $CryptoStream.Write($Data, 0, $Count)
    }
    While ($Count -gt 0)
    $CryptoStream.FlushFinalBlock()
    $CryptoStream.Close()
    $FileStreamWriter.Close()
    $FileStreamReader.Close()
    Copy-Item -Path "$($env:TEMP)\$($FileToDecrypt.Name)" -Destination  $FileToDecrypt.DirectoryName -Force
}

#$filesplit
Write-Output $filesplit

foreach ($file in $FileToDecrypt)
{
Write-Host "Decrypting $file"
Decrypt-File $file $Cert 
}
Exit