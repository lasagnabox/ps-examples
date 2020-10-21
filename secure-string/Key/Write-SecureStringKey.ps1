param (
  [string]$outputPath,
  [string]$keyPath,
  [Parameter(Mandatory=$true)][string]$inputStr
)

If (!$outputPath) {
  If ($psISE) {
    $outputPath = "$(Split-Path -Path $psISE.CurrentFile.FullPath)\Output.txt"
  }
  Else {
    $outputPath = "$PSScriptRoot\Output.txt"
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
# Convert the $inputStr value into a Secure String
$secureStr = $inputStr | ConvertTo-SecureString -AsPlainText -Force
# Convert from SecureString using the specified key rather than letting DPAPI handle it, then export to file
$secureStr | ConvertFrom-SecureString -Key $keyArr | Out-File $outputPath