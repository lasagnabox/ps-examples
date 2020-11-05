param(
    $inputFile = "$(Split-Path $MyInvocation.MyCommand.Path -Parent)\UserInput.csv",
    $apiFile = "$(Split-Path $MyInvocation.MyCommand.Path -Parent)\APIDefs.csv"
)

Function New-RateLimitSleep {
    
    param(
        $unixTime
    )

    $resetTime = (Get-Date "1970-01-01 00:00:00.000Z") + ([TimeSpan]::FromSeconds($unixTime))
    $resetSecond = (New-TimeSpan -End $resetTime).TotalSeconds 
    If ($resetSecond -gt 0) {
        $resetSecond | Sleep
    }
}

Function Invoke-OktaWebRequest {

    param(
        $uri,
        $headers,
        $method,
        $body
    )

    $outputArr = @()
    $pageDone = $null

    If (!$method) {
      $method = 'GET'
    }

    While (!$pageDone) {
        Try{
            If ($body) {
              $req = Invoke-WebRequest -Uri $uri -Headers $headers -ErrorAction Stop -Method $method -Body $body -UseBasicParsing
            }
            Else {
              $req = Invoke-WebRequest -Uri $uri -Headers $headers -ErrorAction Stop -Method $method -UseBasicParsing
            }
            
            $outputArr += $req.Content | ConvertFrom-Json
        }
        # MATT: This is like the nastiest hack and I hate it, but it kinda works when you can't trap specfic errors by Exception type
        Catch{
            If ($_.Exception.Message -like '*429*') {
                While (!$reqDone) {
                    Start-Sleep -Seconds 30
                    Try{
                        If ($body) {
                          $req = Invoke-WebRequest -Uri $uri -Headers $headers -ErrorAction Stop -Method $method -Body $body -UseBasicParsing
                        }
                        Else {
                          $req = Invoke-WebRequest -Uri $uri -Headers $headers -ErrorAction Stop -Method $method -UseBasicParsing
                        }
                        $outputArr += $req.Content | ConvertFrom-Json
                        $reqDone = $true
                    }
                    Catch {}
                }
            }
            Else {
                $req = $null
                Throw "ERROR: URI Request to $uri failed with error message: $($_.Exception.Message)"
            }
        }

        If ($req -and $req.Headers['Link']) {
            $reqNext = $req.Headers['Link'].Split(',') | Where {$_ -like "*rel=`"next`"*"}
        }
        Else {
            $reqNext = $null
        }
        
        If ($reqNext) {
            $uri = $reqNext.Split(';')[0].Trim('<>')
            If ([int]$req.Headers['X-Rate-Limit-Remaining'] -le 2) {
                New-RateLimitSleep -unixTime $req.Headers['X-Rate-Limit-Reset']
            }
        }
        Else {
            If ($req -and [int]$req.Headers['X-Rate-Limit-Remaining'] -le 2) {
                New-RateLimitSleep -unixTime $req.Headers['X-Rate-Limit-Reset']
            }
            $pageDone = $true
        }
    }
    
    Switch ($outputArr.Count) {
        0 {return}
        1 {return $outputArr[0]}
        default {return $outputArr}
    }
}

Function New-PWPush {

  param(
    $password
  )

  $headers = @{
      'Content-Type' = 'application/json'
  }

  $passHash = @{
    password = @{
      payload = $password
      expire_after_days = '60'
      expire_after_views = '5'
    }
  }

  $pwReq = Invoke-RestMethod -Method Post -Headers $headers -Body ($passHash | ConvertTo-Json) -Uri 'https://pwpush.com/p.json'
  return "https://pwpush.com/p/$($pwReq.url_token)"
}

function Convert-DiacriticCharacters {

    param(
        [string]$inputString
    	)
		
    [string]$formD = $inputString.Normalize(
    	[System.text.NormalizationForm]::FormD
    	)
		
    $stringBuilder = new-object System.Text.StringBuilder
    
	For ($i = 0; $i -lt $formD.Length; $i++) {
        $unicodeCategory = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($formD[$i])
        $nonSpacingMark = [System.Globalization.UnicodeCategory]::NonSpacingMark
		
        If ($unicodeCategory -ne $nonSpacingMark) {
            $stringBuilder.Append($formD[$i]) | Out-Null
        	}
    	}
	
    # 04/04/16 - Minor addition to handle characters not caught by automatic detection, 
    $outputStr = $stringBuilder.ToString().Normalize([System.text.NormalizationForm]::FormC)
    
    # Add future replacements to $replaceArr multi-dimensional array in the syntax seen below, including leading comma
    # 18/10/18 - Added ł replacement
    $replaceArr = @(
        ,('ø','o')
        ,('ł','l')
    )
    $replaceArr | ForEach {
        $outputStr = $outputStr.Replace($_[0],$_[1])
    }
    
    $outputStr
}

Function Export-CSVReport {

  param(
    $inputPath,
    $inputArr,
    $reportName
  )

  $dateStr = Get-Date -Format 'yyyyMMddHHmmss'

  $fileNameSplit = (Split-Path $inputPath -Leaf).Split('.')
  If ($reportName) {
    $fileName = "$($fileNameSplit[0])-$reportName-$dateStr.csv"
  }
  Else {
    $fileName = "$($fileNameSplit[0])-$dateStr.csv"
  }
  $outPath = "$(Split-Path $inputPath -Parent)\$fileName"

  $inputArr | Export-CSV $outPath -NoTypeInformation -Encoding UTF8 -Force

}

# Tell PowerShell to use TLS 1.2, as required by Okta
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Web

# Load the input files, build the hash table for looking up the API definitions
$userArr = Import-CSV $inputFile -Encoding UTF8
$apiHash = @{}
$apiArr = Import-CSV $apiFile -Encoding UTF8 | ForEach {$apiHash.Add($_.TenantName,$_)}

$outArr = ForEach ($user in $userArr) {

  $outObj = [PSCustomObject] @{
    Email = $user.Email
    FirstName = ''
    LastName = ''
    PreExisting = ''
    PasswordLink = ''
    Status = ''
  }
  
  # Check if the user definition in the file has a valid tenant listed
  $userTenant = $apiHash["$($user.Tenant)"]

  If ($userTenant) {
    
    # Build the headers you'll need for the next bit
    $oktaHeaders = @{
        Accept = 'application/json'
        'Content-Type' = 'application/json'
        Authorization = "SSWS $($userTenant.APIKey)"
    }
    $oktaTenant = $userTenant.BaseURL

    # Check if user already exists in destination tenant
    $oktaUser = Invoke-OktaWebRequest -uri "https://$($oktaTenant)/api/v1/users?q=$($user.Email)&limit=1" -headers $oktaHeaders
    If ($oktaUser) {
      $outObj.PreExisting = $true
      $outObj.Status = 'ERROR: User already exists in target tenant'
    }
    # If they don't exist, get on with creating them
    Else {
      $outObj.PreExisting = $false
      # Check for blank First/Last names in the input file, replace if they exist
      If ($user.FirstName -eq '' -or $user.LastName -eq '') {
        $user.FirstName = "$($userTenant.TenantName)User"
        $user.LastName = $user.Email
      }

      # Generate a password
      $userPass = "Z4r~$([System.Web.Security.Membership]::GeneratePassword(8,2))"
      $userPassURL = New-PWPush -password $userPass

      # Build the object we need to post for the user creation
      $userOut = [PSCustomObject] @{
        profile = @{
          firstName = (Convert-DiacriticCharacters $user.FirstName.Trim())
          lastName = (Convert-DiacriticCharacters $user.LastName.Trim())
          email = $user.Email.Trim()
          login = $user.Email.Trim()
        }
        credentials = @{
          password = @{
            value = $userpass
          }
        }
        groupIds = @($userTenant.OpusGroupId)
      }

      Try {
        $results = Invoke-OktaWebRequest -uri "https://$($oktaTenant)/api/v1/users?activate=true&nextLogin=changePassword" -headers $oktaHeaders -method 'POST' -body ($userOut | ConvertTo-Json)
        $outObj.FirstName = $results.profile.firstName
        $outObj.LastName = $results.profile.lastName
        $outObj.PasswordLink = $userPassURL
        $outObj.Status = 'Complete'
      }
      Catch {
        $errorUsers += $userOut
        $outObj.Status = "ERROR: Failed to build user with message: $($_.Exception.Message)"
      }
    }
  }
  Else {
    $outObj.Status = "ERROR: No tenant found in API definitions file with name '$($user.Tenant)'"
  }

  $outObj
}

Export-CSVReport -inputPath $inputFile -inputArr $outArr -reportName 'Results'