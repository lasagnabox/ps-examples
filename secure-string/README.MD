# Securely Storing Strings In PS

Just some quick examples of secure string storage in PS using both DPAPI and AES key led encryption

# DPAPI

Leverages the built-in Data Protection API that encryptsstrings in such a way that they can only be decrypted by the user who encrypted it, on the host where the string was encrypted. If it doesn't need to be portable, this is usually the one to go for.

### Usage
Write string to file securely using DPAPI:
```
powershell .\Write-SecureStringDPAPI.ps1 -outputPath <fullPathToOutputFile> -inputStr <TextForEncryption>
```
Read DPAPI encrypted string from file:
```
powershell .\Read-SecureStringDPAPI.ps1 -inputPath <fullPathToInputFile>
```


# AES Key

Adds an extra step, generating a random 256-bit AES compatible key that's used to encrypt the data before it's written to disk instead of allowing DPAPI to handle it. Can be decrypted by anyone with the key file on any host.

### Usage
Generate new 256-bit AES encryption key:
```
.\New-KeyFile.ps1 -outputPath <fullPathToKeyFile>
```
Write string encrypted using specified key to file:
```
.\Write-SecureStringKey.ps1 -keyPath <fullPathToKeyFile> -outputPath <fullPathToOutputFile> -inputStr <TextForEncryption>
```
Read encrypted string from file using key:
```
.\Read-SecureStringKey.ps1 -keyPath <fullPathToKeyFile> -inputPath <fullPathToInputFile>
```

# Quick Notes
 - Either of these methodologies should always be combined with restrictive file permissions
 - Don't use your own creds for storing/retrieving via DPAPI, create a dedicated service account. Often this can just be a local account on whatever script host box you're running it on.