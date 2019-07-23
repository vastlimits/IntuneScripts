#Requires -RunAsAdministrator
#Requires -Version 3

<#
.SYNOPSIS
   - Disable Microsoft Office macro execution, by querying all currently logged on users (a running shell (explorer.exe)) and setting the appropriate values via registry under HKU:\<SID>\SOFTWARE\Policies\Microsoft\Office
   - Disable Microsoft Office DDE execution (https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440)
   - Disable web search in start menu by modifying BingSearchEnabled and CortanaConsent values
.NOTES
   Author:  vast limits GmbH
   Version: 1.0.3
.DESCRIPTION
   1.0.3:   As the only product, Outlook does not use 'VBAWarnings' for controlling macro behaviour. Instead 'Level' is being used   
   1.0.2:   Fixed an error while determining the 'HKU:\<SID>\SOFTWARE\Policies\Microsoft\Office' path
   1.0.1:   Minor bugfixes
   1.0.0:   Initial release
#>

Try {
   #region variables
   # Adjust variables to your needs
   $ErrorActionPreference = 'Continue'
   
   If(!(Test-Path -Path "$env:programdata\vast limits")) { New-Item -Path $env:programdata -Name "vast limits" -ItemType Directory -Force }
   $ScriptPath = "$env:programdata\vast limits\"
   $Log = "vlComplianceSettings.log"
   Start-Transcript -Path $($ScriptPath+$Log) | Out-Null
   
   $LoggedOnUsers = @{}
   
   $OfficeVersions = @(
   "16.0", #2016, 2019, 365
   "15.0", #2013
   "14.0", #2010
   "12.0", #2007
   "11.0") #2003

   $MacroKeys = @(
   "Access\Security",
   "Excel\Security",
   "MS Project\Security",
   "Outlook\Security",
   "PowerPoint\Security",
   "Publisher\Security",
   "Visio\Security",
   "Word\Security")    
   #endregion

   Write-Verbose "Querying logged on user(s) and determining SID." -Verbose
   (Get-Process -Name explorer -IncludeUserName).Username | ForEach {$LoggedOnUsers.Add( $_, ((New-Object security.principal.ntaccount $_).translate([security.principal.securityidentifier]).Value))}    
   Write-Verbose "Creating PSDrive for HKU." -Verbose
   New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

   Write-Verbose ">> Disable Microsoft Office macro execution." -Verbose
   ForEach($sid in $LoggedOnUsers.Values) {
      Write-Verbose "> Processing SID $sid" -Verbose
      ForEach($version in $OfficeVersions) {
         Push-Location
         If(Test-Path -Path "HKU:\$sid\SOFTWARE\Microsoft\Office\$version\") {
            Write-Verbose "Detected Office $version" -Verbose         
            If(!(Test-Path -Path "HKU:\$sid\SOFTWARE\Policies\Microsoft\Office\$version\")) { New-Item -Path "HKU:\$($sid)\SOFTWARE\Policies\Microsoft\Office\$($version)\" -Force | Out-Null }
            Set-Location -Path "HKU:\$sid\SOFTWARE\Policies\Microsoft\Office\$version\"
               ForEach($macrokey in $MacroKeys) {
                  If($macrokey -match "Outlook") { $macrocontrolkey = "Level" }
                  Else { $macrocontrolkey = "VBAWarnings" }
                  
                  If(Test-Path -Path (-join("$((Get-Location).Path)","$($macrokey)"))) { New-ItemProperty -Name $macrocontrolkey -Path (-join("$((Get-Location).Path)","$($macrokey)")) -PropertyType DWORD -Value 4 -Force | Out-Null }
                  Else { New-Item -Name $macrokey -Force | New-ItemProperty -Name $macrocontrolkey -PropertyType DWORD -Value 4 -Force | Out-null }
               }
               Write-Verbose "Office $version macros disabled."  -Verbose
         }
         Pop-Location
      }
   }

   Write-Verbose ">> Disable Microsoft Office Dynamic Data Exchange (DDE) execution." -Verbose
   ForEach($sid in $LoggedOnUsers.Values) {
	   Write-Verbose "> Processing SID $sid" -Verbose
      ForEach($version in $OfficeVersions) {
         Push-Location
         If(Test-Path -Path "HKU:\$sid\SOFTWARE\Microsoft\Office\$version\") {
            Write-Verbose "Detected Office $version" -Verbose
            Set-Location -Path "HKU:\$sid\SOFTWARE\Microsoft\Office\$version\"
            If($version -ge "14.0") {
               If(Test-Path (-join("$((Get-Location).Path)","Excel\Security\"))) { New-ItemProperty -Name "WorkbookLinkWarnings" -Path (-join("$((Get-Location).Path)","Excel\Security\")) -PropertyType DWORD -Value 2 -Force | Out-Null }
               Else { New-Item -Name "Excel\Security\" -Force | New-ItemProperty -Name "WorkbookLinkWarnings" -PropertyType DWORD -Value 2 -Force | Out-Null }
                
					If(Test-Path (-join("$((Get-Location).Path)","Word\Options\"))) { New-ItemProperty -Name "DontUpdateLinks" -Path (-join("$((Get-Location).Path)","Word\Options\")) -PropertyType DWORD -Value 1 -Force | Out-Null }
               Else { New-Item -Name "Word\Options\" -Force | New-ItemProperty -Name "DontUpdateLinks" -PropertyType DWORD -Value 1 -Force | Out-Null }
					
					If(Test-Path (-join("$((Get-Location).Path)","Word\Options\WordMail"))) { New-ItemProperty -Name "DontUpdateLinks" -Path (-join("$((Get-Location).Path)","Word\Options\WordMail")) -PropertyType DWORD -Value 1 -Force | Out-Null }
               Else { New-Item -Name "Word\Options\WordMail" -Force | New-ItemProperty -Name "DontUpdateLinks" -PropertyType DWORD -Value 1 -Force | Out-Null }
					
               Write-Verbose "Office $version DDE execution disabled." -Verbose
            }
				ElseIf($version -eq "12.0") {
					If(Test-Path (-join("$((Get-Location).Path)","Word\Options\vpref"))) { New-ItemProperty -Name "fNoCalclinksOnopen_90_1" -Path (-join("$((Get-Location).Path)","Word\Options\vpref")) -PropertyType DWORD -Value 1 -Force | Out-Null }
               Else { New-Item -Name "Word\Options\vpref" -Force | New-ItemProperty -Name "fNoCalclinksOnopen_90_1" -PropertyType DWORD -Value 1 -Force | Out-Null }
            
               Write-Verbose "Office $version DDE execution disabled." -Verbose
            }
				Else { Write-Verbose "No applicable Microsoft Office version detected." -Verbose }
			}
         Pop-Location
      }
   }

   Write-Verbose ">> Disable web search in start menu." -Verbose
   ForEach($sid in $LoggedOnUsers.Values) {
      Write-Verbose "> Processing SID $sid" -Verbose
      Push-Location
      If(Test-Path -Path "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Search\") {
         Set-Location -Path "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Search\"
         New-ItemProperty -Name "BingSearchEnabled" -Path $((Get-Location).Path) -PropertyType DWORD -Value 0 -Force | Out-Null
         New-ItemProperty -Name "CortanaConsent" -Path $((Get-Location).Path) -PropertyType DWORD -Value 0 -Force  | Out-Null
      }
      Else {
         New-Item -Path "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Search" -Force | Set-Location
         New-ItemProperty -Name "BingSearchEnabled" -Path $((Get-Location).Path) -PropertyType DWORD -Value 0 -Force | Out-Null
         New-ItemProperty -Name "CortanaConsent" -Path $((Get-Location).Path) -PropertyType DWORD -Value 0 -Force | Out-Null
      }
      Write-Verbose "Start menu web search disabled." -Verbose
      Pop-Location
   } 
}

Catch {
   ErrorMessage = $_.Exception.Message
   Write-Error $ErrorMessage
}

Finally {
   Stop-Transcript | Out-Null
}