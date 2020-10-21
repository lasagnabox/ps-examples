param (
  [string]$outputPath
)

If (!$outputPath) {
  If ($psISE) {
    $outputPath = "$(Split-Path -Path $psISE.CurrentFile.FullPath)\Key.txt"
  }
  Else {
    $outputPath = "$PSScriptRoot\Key.txt"
  }
}

# Create the appropriately sized byte array
$key = New-Object byte[](32)
# Call the built-in RNGCryptoServiceProvider to generate random data
$rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
# Populate the byte array with the random values created
$rng.GetBytes($key)
# Export to file for later reference
$key | Out-File $outputPath