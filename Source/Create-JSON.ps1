#Requires -Version 5.0
<#
.SYNOPSIS
  This is designed to create org settings files that are used by the SCAPer tool.
.DESCRIPTION
  This will take a STIG checklist and STIG modules and create an orgsettings file with all the non-checked STIGS
.INPUTS
  You will need to provide the checklist and the modules themselves.
.OUTPUTS
  Log file named Create-JSON.log stored in the Logs folder at the root of the SCAPer tool.
.NOTES
  Version:        1.1
  Author:         Michael Calabrese
  Creation Date:  1/30/2022
  Edit Date:      1/30/2022
  Purpose/Change: Initial Script Development
  ToDo List:
    - Multiple checklist support. 83 NOS uses a couple different checklists per quarter.
    - Write an example
  
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>

#Initialize
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
$ckl = @()
$orgexport = @()

#Load functions
. (Join-Path $sourceFolder 'Functions.ps1')

#Start logging, this is going to help in the long run
Start-Transcript (Join-Path $logFolder 'Create-JSON.log') -Force | Out-Null

#Prompt for New STIG Checklist
$cklfile = New-Object System.Windows.Forms.OpenFileDialog
$cklfile.Filter = "Checklist | *.ckl"
$cklfile.Title = "Select checklist to compare with."
$cklfile.InitialDirectory = $checklistFolder
[Void]$cklfile.ShowDialog()

if([bool]$cklfile.FileName) {
    Write-Host "Imported $($cklfile.FileName) as Checklist." -ForegroundColor Cyan
} else {
    #if no checklist selected exit
    Continue
}

#Prompt for PS STIG Modules, multiple allowed
$STIGModules = New-Object System.Windows.Forms.OpenFileDialog
$STIGModules.Filter = "PS Module | *.psm1"
$STIGModules.Title = "Select PowerShell Module(s) to upgrade."
$STIGModules.InitialDirectory = $STIGFolder
$STIGModules.Multiselect = $true
[Void]$STIGModules.ShowDialog()

if([bool]$STIGModules.FileName) {
    Write-Host "Imported the following Modules to update:`n$($STIGModules.FileNames -join "`n")" -ForegroundColor Cyan
} else {
    #if no STIGS selected exit
    Continue
}

#Turn checklist to an array
Write-Host "Parsing New STIGs" -ForegroundColor Cyan
$ckl = Parse-STIGS -cklFile (Get-Content $cklfile.FileName)

#Start main loop
foreach($STIGModule in $STIGModules.FileNames) {
    #Initiate vars
    $benchmarkName = $null

    #Import the STIG Module's contents
    Write-Host "Importing file: $STIGModule" -ForegroundColor Cyan
    $module=Get-Content $STIGModule
    
    #Identify the type of module with some "fun" regex
    $ModuleType = (($STIGModule.Split('\')[-1]) -replace ' STIG V.R.+.psm1','') -replace '&','/'
    Write-Host "ModuleType: `'$ModuleType`' detected" -ForegroundColor Cyan

    #Match the module type to a benchmark name
    $benchmarkName=$ckl.Benchmark | Where-Object {$_ -match $ModuleType} | Select-Object -First 1

    if($null -eq $benchmarkName) {
        Write-Warning "Old Checklist does not contain this STIG type, skipping."
        Continue
    }
    
    Write-Host "STIG: $benchmarkName" -ForegroundColor Cyan

    <############################################################################
    Experimental-----This is the meat and potatoes of the script-----Experimental
    This section gives a pretty verbose output of what is happening in the script
    ############################################################################>

    <#We're going to grab each entry in the checklist and compare it against the
    old STIG, the new STIG, and the org settings file if it exists#>
    foreach($entry in ($ckl | Where-Object {$_.Benchmark -eq $benchmarkName} )) {
        Write-Host "`nProcessing $($entry.Vuln_ID)."

        #Check to see if the Vuln_ID is already in the module
        if($module -match $entry.Vuln_ID) {
            Write-Host "Module contains $($entry.Vuln_ID)." -ForegroundColor Green
        } else {
            #Generate a Manual_Entries object for each VulnId with no match
            Write-Host "Creating entry for $($entry.Vuln_ID)." -ForegroundColor Yellow
            $orgexport += [pscustomobject]@{
                Vuln_ID = $_.Vuln_ID
                Benchmark = $_.Benchmark
                Rule_Title = $_.Rule_Title
                Rule_ID = $_.Rule_ID
                Status = "Not_Reviewed"
                Comment = ""
            }
        }
    }
}
    
#Generate the JSON file template
$orgsettingstemplate = [pscustomobject]@{
    Title = "Manual STIG Entries"
    FRs = @()
    POAMS = @()
    Locations =[ pscustomobject]@{
        MFRs = ''
        POAMS = ''
    }
    Manual_Entries = $orgexport
}

#Export the orgsettingstemplate
$orgsettingstemplate | ConvertTo-Json | Out-File (Join-Path $orgSettingsFolder 'NewOrgTemplate.json') -Encoding default -Force

Stop-Transcript -ErrorAction SilentlyContinue
Write-Host "Control Returned to the launcher."