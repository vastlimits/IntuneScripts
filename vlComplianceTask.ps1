#Requires -RunAsAdministrator
#Requires -Version 3

<#
.SYNOPSIS
   This script creates a scheduled task running as LOCAL SYSTEM with multiple triggers (once per hour, on workstation unlock & on logon) and executes a specified script.
.NOTES
   Author: vast limits GmbH
   Version: 1.0.2
.DESCRIPTION
   1.0.2:  Added modfication of the 'Author' attribute
   1.0.1:  Modified script call with '-ExecutionPolicy Bypass', in case the local security policy prevents the execution of PowerShell scripts
   1.0:    Initial release
#>

Try {
   #region variables
   # Adjust variables to your needs
   $ErrorActionPreference = 'Continue'
   $ScriptPath = "$env:programdata\vast limits\"
   $Log = "vlComplianceTask.log"
   $Script = "vlComplianceSettings.ps1"
   $TaskName = "vl Compliance"
   $TaskAuthor = "vast limits GmbH"

   If(!(Test-Path -Path $ScriptPath)) { New-Item -Path $env:programdata -Name "vast limits" -ItemType Directory -Force }
   Start-Transcript -Path $($ScriptPath+$Log) | Out-Null
   #endregion

   # define action
   $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -file `"$($ScriptPath+$Script)`""
   # define task settings
   $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -ExecutionTimeLimit 00:30:00
   # define task user
   $User = "NT AUTHORITY\SYSTEM"
   # define trigger 1: every hour
   $Trigger1 = New-ScheduledTaskTrigger -Once -RepetitionInterval 01:00:00 -At 00:00:00 
   # define trigger 2: user logon
   $Trigger2 = New-ScheduledTaskTrigger -Atlogon
   # define trigger 3: user unlock //TASK_SESSION_STATE_CHANGE_TYPE.TASK_SESSION_UNLOCK (taskschd.h)
   $Trigger3 = New-CimInstance -CimClass $(Get-CimClass -Namespace ROOT\Microsoft\Windows\TaskScheduler -ClassName MSFT_TaskSessionStateChangeTrigger) -Property @{StateChange = 8} -ClientOnly 
   # Register scheduled Task
   Register-ScheduledTask -Force -User $User -TaskName $TaskName -Action $Action -Trigger $Trigger1, $Trigger2, $Trigger3 -Settings $Settings | Out-Null
   $task = Get-ScheduledTask -TaskName $TaskName
   $task.Author = $TaskAuthor
   $task | Set-ScheduledTask | Out-Null
   Write-Verbose "Scheduled Task $TaskName registered successfully." -Verbose
}

Catch {
   $ErrorMessage = $_.Exception.Message
   Write-Error $ErrorMessage
}

Finally {
   Stop-Transcript | Out-Null
}