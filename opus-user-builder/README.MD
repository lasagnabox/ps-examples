# WMG Okta - Opus User Builder

This script is a PowerShell based solution to automate the mass provisioning of new Okta users specifically for access to Opus, driven from CSV files.

## Requirements

 - API keys with the rights to create users in the Opus groups for each tenant you wish to work provision users into

## Usage

The input to the script is driven via two CSV files:

**NOTE: The files in this repo contain example entries which must be removed / updated before running this for the first time!**

### APIDefs.csv

| Field Name | Description | Mandatory | Usage | Example Value |
| ----- | ----- | ----- | ----- | ----- |
| TenantName | The name of the Okta tenant this definition is for | Yes | Tenant mapping in UserInput.csv, component of user FirstName fields in specific scenarios | Partners |
| BaseURL | URL of target Okta tenant | Yes | Target for Okta API calls | wmgpartners.okta.com |
| OpusGroupId | The Okta groupId for the Opus assignment group users will be added to in target Okta tenant | Yes | Target group for user provisioning | 00gqlqyawgfylCxcK4x6 |
| APIKey | Okta API key with appropriate administrative rights in target tenant | Yes | Authentication to Okta tenant for API calls | 00_igeKnBwocWUt5xrtOZ64LxxWjjRLX-2wxq4v7 |

**NOTE: This file will contain API keys which MUST be treated carefully. Do not commit these files to repos, or store them on shared drives.**

### UserInput.csv

| Field Name | Description | Mandatory | Usage | Example Value |
| ----- | ----- | ----- | ----- | ----- |
| Email | The email address for the user | Yes | User login to Okta | matt.cummins@fakemail.com |
| FirstName | User's first name | Yes | FirstName of Okta user | Matt |
| LastName | User's last name | Yes | LastName of Okta user | Matt |
| Tenant | One of the TenantName entries declared in APIDefs.csv | Yes | Target for which Okta tenant the user should be created in | Partners |
| GeneratePassword | If blank, user will be activated immediately with a one-time email from Okta for them to set their own password. If this field has any value, the user will have a password randomly generated to be communicated directly to them at a later date, a disposable link to which will be found in the output CSV | No | Determines method of user credential generation & communication | TRUE |
| SkipActivation | If blank, will activate Okta user as part of creation process. If this field has any value, users will be created with STAGED status for later activation | No | Determines if user is created activated or not | TRUE |

Once the CSVs have been populated, the script can be invoked like this:
```
powershell -File <full_path_to_script> -inputFile <full_path_to_UserInput_csv> -apiFile <full_path_to_ApiDefs_csv>
```

## Outputs

Each run will produce a CSV file which will detail the user status, any errors encountered, and will include the disposable password links for users where appropriate. This will be created in the same directory as the inputFile that was passed to the script at runtime.

## Contact

Written & maintained by matt.cummins@warnermusic.com