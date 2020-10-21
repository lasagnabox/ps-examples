param (
  [string]$inputPath = "$PSScriptRoot\Output.txt"
)

If ($inputPath) {
  If ($psISE) {
    $inputPath = "$(Split-Path -Path $psISE.CurrentFile.FullPath)\Output.txt"
  }
  Else {
    $inputPath = "$PSScriptRoot\Output.txt"
  }
}

# Read in the input file and convert it to a SecureString using the current user/machine context with DPAPI
$secureStr = Get-Content $inputPath | ConvertTo-SecureString

# If you wanted to use the string you just read in as a credential object to call another user account:
$credentialObj = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'WhateverAccountName',$secureStr

# Everything below is just for demonstrating that the decryption process is working, usually you'd be working with the contensts of $secureStr anyhow
If ($secureStr) {
  $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureStr)
  $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
  $PlainPassword
}