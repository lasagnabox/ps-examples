param (
  [string]$inputPath,
  [string]$keyPath
)

If (!$inputPath) {
  If ($psISE) {
    $inputPath = "$(Split-Path -Path $psISE.CurrentFile.FullPath)\Output.txt"
  }
  Else {
    $inputPath = "$PSScriptRoot\Output.txt"
  }
}

If (!$keyPath) {
  If ($psISE) {
    $keyPath = "$(Split-Path -Path $psISE.CurrentFile.FullPath)\Key.txt"
  }
  Else {
    $keyPath = "$PSScriptRoot\Key.txt"
  }
}

# Read in the contents of the key file
$keyArr = Get-Content $keyPath
# Read in the input file and convert it to a SecureString using the keyArr
$secureStr = Get-Content $inputPath | ConvertTo-SecureString -Key $keyArr

# If you wanted to use the string you just read in as a credential object to call another user account:
$credentialObj = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'WhateverAccountName',$secureStr

# Everything below is just for demonstrating that the decryption process is working
If ($secureStr) {
  $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureStr)
  $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
  $PlainPassword
}