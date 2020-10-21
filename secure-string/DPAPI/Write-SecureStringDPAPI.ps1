param (
  [string]$outputPath,
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

# Convert the inputStr to SecureString
$secureStr = $inputStr | ConvertTo-SecureString -AsPlainText -Force
# Export to file using DPAPI to store it as decryptable only by current user on current host
$secureStr | ConvertFrom-SecureString | Out-File $outputPath -Force