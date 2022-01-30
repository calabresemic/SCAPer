#Requires -Version 5.0
<#
.SYNOPSIS
  This is designed to safely update the STIG modules that are used by the SCAPer tool.
.DESCRIPTION
  I made this script because I hate DISA and I need a way to convert all their bullsh*t numbers to other bullsh*t numbers
  There's honestly no way to be 100% sure that this will really do everything correct but it'll get you damn close.
  Please look me up DISA, I've got words for you.
.INPUTS
  You will need to provide at a minimum the old checklist that matches your modules
  and the new checklist to update to, as well as the modules themselves.
  You also can provide your current OrgSettings file to update it along with the modules.
.OUTPUTS
  Log file named ModuleUpdater.log stored in the Logs folder at the root of the SCAPer tool.
.NOTES
  Version:        1.1
  Author:         Michael Calabrese
  Creation Date:  Unknown date in 2021
  Edit Date:      1/30/2022
  Purpose/Change: Retool this to work with the SCAPer more natively.
  ToDo List:
    - Multiple checklist support. 83 NOS uses a couple different checklists per quarter.
    - Write an example
  
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>

#Initialize
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
$Oldckl=@()
$Newckl=@()

#Load functions
. (Join-Path $sourceFolder 'Functions.ps1')

#Start logging, this is going to help in the long run
Start-Transcript (Join-Path $logFolder 'ModuleUpdater.log') -Force | Out-Null

#Prompt for Old STIG Checklist
$oldSTIGSfile = New-Object System.Windows.Forms.OpenFileDialog
$oldSTIGSfile.Filter = "Checklist | *.ckl"
$oldSTIGSfile.Title = "Select old checklist to compare against."
$oldSTIGSfile.InitialDirectory = $checklistFolder
[Void]$oldSTIGSfile.ShowDialog()

if([bool]$oldSTIGSfile.FileName) {
    Write-Host "Imported $($oldSTIGSfile.FileName) as Old Checklist." -ForegroundColor Cyan
} else {
    #if no checklist selected exit
    Continue
}

#Prompt for New STIG Checklist
$newSTIGSfile = New-Object System.Windows.Forms.OpenFileDialog
$newSTIGSfile.Filter = "Checklist | *.ckl"
$newSTIGSfile.Title = "Select new checklist to compare with."
$newSTIGSfile.InitialDirectory = $checklistFolder
[Void]$newSTIGSfile.ShowDialog()

if([bool]$newSTIGSfile.FileName) {
    Write-Host "Imported $($newSTIGSfile.FileName) as New Checklist." -ForegroundColor Cyan
} else {
    #if no checklist selected exit
    Continue
}

#Prompt for Org Settings File
$OrgSettingsfile = New-Object System.Windows.Forms.OpenFileDialog
$OrgSettingsfile.Filter = "Org Settings | *.json"
$OrgSettingsfile.Title = "Select Org Settings file."
$OrgSettingsfile.InitialDirectory = $orgSettingsFolder
[Void]$OrgSettingsfile.ShowDialog()

if([bool]$OrgSettingsfile.FileName) {
    $hasOrgSettings=$true
    Write-Host "Imported org settings file: $($OrgSettingsfile.FileName)" -ForegroundColor Cyan
    $orgsettings = Get-Content $OrgSettingsfile.FileName
} else {
    $hasOrgSettings=$false
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

Write-Host "Creating output files" -ForegroundColor Cyan
New-Item (Join-Path $moduleUpdaterFolder 'ManuallyVerify.csv') -Force | Out-Null
New-Item (Join-Path $moduleUpdaterFolder 'RemoveFromModules.txt') -Force | Out-Null

#Turn checklists to arrays
Write-Host "Parsing Old STIGs" -ForegroundColor Cyan
$Oldckl = Parse-STIGS -cklFile (Get-Content $oldSTIGSfile.FileName)

Write-Host "Parsing New STIGs" -ForegroundColor Cyan
$Newckl = Parse-STIGS -cklFile (Get-Content $newSTIGSfile.FileName)

#Start main loop
foreach($STIGModule in $STIGModules.FileNames) {
    #Initiate arrays and vars
    $NoMatch=@()
    $ManVer=@()
    $Export=@()
    $orgexport=@()
    $scriptmiss=@()
    $OldSTIG=$null
    $NewSTIG=$null

    #Import the STIG Module's contents
    Write-Host "Importing file: $STIGModule" -ForegroundColor Cyan
    $module=Get-Content $STIGModule
    
    #Identify the type of module with some "fun" regex
    $ModuleType = (($STIGModule.Split('\')[-1]) -replace ' STIG V.R.+.psm1','') -replace '&','/'
    Write-Host "ModuleType: `'$ModuleType`' detected" -ForegroundColor Cyan

    #Match the module type to a benchmark name
    $oldSTIG=$Oldckl.Benchmark | Where-Object {$_ -match $ModuleType} | Select-Object -First 1
    $newSTIG=$Newckl.Benchmark | Where-Object {$_ -match $ModuleType} | Select-Object -First 1

    if($oldSTIG -eq $null) {
        Write-Warning "Old Checklist does not contain this STIG type, skipping."
        Continue
    } elseif($newSTIG -eq $null) {
        Write-Warning "New Checklist does not contain this STIG type, skipping."
        Continue
    } elseif($oldSTIG -eq $newSTIG) {
        Write-Warning "Old STIG Matches New STIG, skipping."
        Continue
    }
    
    Write-Host "Old STIG: $oldSTIG" -ForegroundColor Cyan
    Write-Host "New STIG: $newSTIG" -ForegroundColor Cyan

    #Turn that new STIG name into a file name that I can read later
    $newSTIG -match "^(.+) Security Technical Implementation Guide :: Version (\d+), Release: (\d+)" | Out-Null
    $fileName = "{1} STIG V{2}R{3}.psm1" -f $matches[0],$matches[1],$matches[2],$matches[3] -replace '/','&'
    $filePath = (Join-Path $moduleUpdaterFolder "STIGS\$fileName")

    #Check if it exists
    if(Test-Path $filePath) {
        Write-Warning "New Module Already Exists , skipping."
        Continue
    }

    <############################################################################
    Experimental-----This is the meat and potatoes of the script-----Experimental
    This section gives a pretty verbose output of what is happening in the script
    ############################################################################>

    <#We're going to grab each entry in the checklist and compare it against the
    old STIG, the new STIG, and the org settings file if it exists#>
    foreach($entry in ($Newckl | Where-Object {$_.Benchmark -eq $NewSTIG} )) {
        
        $match=$false #Set up tracker since the org settings shouldn't contain the same vulns as the module
        Write-Host "`nProcessing $($entry.Vuln_ID)."

        #Check to see if the Vuln_ID is already in the module
        if($module -match $entry.Vuln_ID) {
            Write-Host "Module contains $($entry.Vuln_ID)." -ForegroundColor Yellow

            #Check to see if the Rule_ID is already in the module
            if($module -match $entry.Rule_ID) {
                #if this occurs there is no change to both the VulnId and the RuleId
                Write-Host "Rule_ID is a match, no action taken." -ForegroundColor Green
                $match = $true
            } else {
                Write-Host "Module Rule_ID is not a match." -ForegroundColor Yellow

                #Try to match the vulnId to the old STIG
                [array]$old=$oldckl | Where-Object {$_.Vuln_ID -EQ $entry.Vuln_ID}
                if($old.Count -gt 0) {
                    Write-Host "Old Rule_ID found." -ForegroundColor Yellow

                    #If something matches, check the CheckText to see if the rule updated.
                    if($entry.CheckText -eq $old.CheckText) {
                        #If this occurs, the RuleId updated but the checktext stayed the same. Really common for DISA.
                        Write-Host "Check Text Matches, updating Rule_ID." -ForegroundColor Green
                        $module = $module -replace "^Function $($old.Rule_ID) {.*$","Function $($entry.Rule_ID) {"
                        $match = $true
                    } else {
                        <#If the checktext changed this needs to be manually reviewed.
                        I might come back later and trim spaces to see if I can remove the 
                        possibility of them changing the ammount of new lines in the checktext randomly.#>
                        Write-Warning "Check Text NOT a Match, adding to Manual Verify list."
                        $entry | Add-Member -Type NoteProperty -Name LegacyRule_ID -Value $old.Rule_ID -Force
                        $ManVer += $entry
                        $match = $true
                    }
                }
            }
        } else {
            <#The old STIG did not have this VulnId. Check to see if this is a legacy Vuln_ID
            based on the new value provided by DISA late 2021.#>
            Write-Host "Script does not contain $($entry.Vuln_ID)" -ForegroundColor Yellow
            [array]$old = $oldckl | Where-Object {$_.Vuln_ID -EQ $entry.legacy_ID}
            
            if($old.Count -gt 0) {
                #If this occurs, I found a match to the VulnId
                Write-Host "Legacy Vuln $($old.Vuln_ID) Exists" -ForegroundColor Yellow

                if($entry.CheckText -eq $old.CheckText) {
                    #If this occurs, the VulnID and RuleId updated but the checktext stayed the same.
                    #Really common for DISA when rolling to a new numbering scheme.
                    Write-Host "Check Text Matches, updating Rule_ID and Vuln_ID." -ForegroundColor Green
                    $module = $module -replace "^Function $($old.Rule_ID) {.*$","Function $($entry.Rule_ID) {"
                    $module = $module -replace "^#$($old.Vuln_ID).*$","#$($entry.Vuln_ID)"
                    $match=$true

                    #Now check to see if there's a POAM or MFR for the old VulnId
                    if($orgsettings -match "^.+`"$($old.Vuln_ID)`",$") {
                        Write-Host "MFR or POAM for $($entry.Vuln_ID) exists, Updating Vuln_ID" -ForegroundColor Green
                        $orgsettings=$orgsettings -replace "`"$($old.Vuln_ID)`"","`"$($entry.Vuln_ID)`""
                    }
                } else {
                    #If this occurs the check text changed. Someone needs to lay eyes on it.
                    Write-Warning "Check Text is NOT a Match, adding to Manual Verify list."
                    $entry | Add-Member -Type NoteProperty -Name LegacyRule_ID -Value $old.Rule_ID
                    $ManVer += $entry
                    $match = $true
                }
            } else {
                #If this occurs there was no matched found anywhere. Maybe it's new.
                Write-Warning "Unable to find a Legacy Vuln match for $($entry.Vuln_ID)."
            }
        }
        
        #If there wasn't a match in the module, check the orgsettings file.
        if($hasOrgSettings -and !($match)) {

            #Check to see if the Vuln_ID is already in the orgsettings
            if($orgsettings -match $entry.Vuln_ID) {
                #If this occurs, the VulnId is in the orgsettings file
                Write-Host "OrgSettings contain $($entry.Vuln_ID)." -ForegroundColor Yellow
                
                #Check to see if the Rule_ID is already in the orgsettings
                if($orgsettings -match $entry.Rule_ID) {
                    #RuleId matches, do nothing.
                    Write-Host "Rule_ID is a match, no action taken." -ForegroundColor Green
                } else {
                    #No match
                    Write-Host "OrgSetting Rule_ID is not a match." -ForegroundColor Yellow
                    [array]$old = $oldckl | Where-Object {$_.Vuln_ID -EQ $entry.Vuln_ID}

                    if($old.Count -gt 0) {
                        #If something matches, check the CheckText to see if the rule updated.
                        Write-Host "Old Rule_ID found." -ForegroundColor Yellow
                        if($entry.CheckText -eq $old.CheckText) {
                            #If this occurs, the RuleId updated but the checktext stayed the same. Really common for DISA.
                            Write-Host "Check Text Matches, updating Rule_ID." -ForegroundColor Green
                            $orgsettings = $orgsettings -replace "`"Rule_ID`":  `"$($old.Rule_ID)`",$","`"Rule_ID`":  `"$($entry.Rule_ID)`","
                        } else {
                            <#If the checktext changed this needs to be manually reviewed.
                            I might come back later and trim spaces to see if I can remove the 
                            possibility of them changing the ammount of new lines in the checktext randomly.#>
                            Write-Warning "Check Text NOT a Match, adding to Manual Verify list."
                            $entry | Add-Member -Type NoteProperty -Name LegacyRule_ID -Value $old.Rule_ID -Force
                            $ManVer += $entry
                        }
                    }
                }
            } else {
                #Check to see if this is a legacy Vuln_ID
                Write-Host "OrgSettings do not contain $($entry.Vuln_ID)" -ForegroundColor Yellow
                [array]$old = $oldckl | where Vuln_ID -EQ $entry.legacy_ID

                if($old.Count -gt 0) {
                    Write-Host "Legacy Vuln $($old.Vuln_ID) Exists" -ForegroundColor Yellow
                    if($entry.CheckText -eq $old.CheckText) {
                        #If this occurs, the VulnID and RuleId updated but the checktext stayed the same.
                        #Really common for DISA when rolling to a new numbering scheme.
                        Write-Host "Check Text Matches, updating Rule_ID and Vuln_ID." -ForegroundColor Green
                        $orgsettings=$orgsettings -replace "`"Rule_ID`":  `"$($old.Rule_ID)`",$","`"Rule_ID`":  `"$($entry.Rule_ID)`","
                        $orgsettings=$orgsettings -replace "`"$($old.Vuln_ID)`"","`"$($entry.Vuln_ID)`""
                    } else {
                        #If this occurs the check text changed. Someone needs to lay eyes on it.
                        Write-Warning "Check Text is NOT a Match, adding to Manual Verify list."
                        $entry | Add-Member -Type NoteProperty -Name LegacyRule_ID -Value $old.Rule_ID
                        $ManVer += $entry
                    }
                } else {
                    #No match
                    Write-Warning "Unable to find a Legacy Vuln match for $($entry.Vuln_ID)."
                    $NoMatch += $entry
                }
            }
        }
    }

    #Export the module after we did all this editing
    Write-Host "Exporting new module to $filePath" -ForegroundColor Cyan 
    $module = $module -replace $OldSTIG,$NewSTIG #Replace STIG Name
    $module | Out-File $filePath -Encoding default

    #If there's an orgsettings file export that as well
    if($hasOrgSettings) {
        $newOrgSettingsFilePath = $OrgSettingsfile.FileName.Replace('.json','_new.json')
        Write-Host "Exporting new OrgSettings to $newOrgSettingsFilePath" -ForegroundColor Cyan 
        $orgsettings = $orgsettings -replace $OldSTIG,$NewSTIG #Replace STIG Name
        $orgsettings | Out-File $newOrgSettingsFilePath -Encoding default -Force
    }

    #Creates a template with new STIGs
    if($NoMatch) {
        Write-Host "New STIGs were found exporting template to $(Join-Path $moduleUpdaterFolder 'STIGS\NEWSTIGS-$FileName.psm1')" -ForegroundColor Cyan
        $NoMatch.ForEach({
            if($Export -match $_.Vuln_ID) {
                <#Man I have no clue why this doesn't work any other way#>
            } else {
                $Export += @"
#$($_.Vuln_ID)
#$($_.Rule_Title)
Function $($_.Rule_ID) {
    #Comments detailing the GPO setting path
    #Comments describing the setting to configure and what to set it to
    if (stigSettingsDontApply) {
        return [pscustomobject]@{
            Status='Not_Applicable'
            Comment=''
            Finding_Details=''
        }
    } elseif (SettingAreConfiguredAsDesired) {
        return [pscustomobject]@{
            Status='NotAFinding'
            Comment=''
            Finding_Details=''
        }
    } else {
        return [pscustomobject]@{
            Status='Open'
            Comment=''
            Finding_Details=''
        }
    }
}

"@
                #Generate a Manual_Entries object for each VulnId with no match
                if($hasOrgSettings) {
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
        })

        #Generate the JSON file template
        if($hasOrgSettings) {
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
        }
        
        #Export the new STIGS to a module
        $Export | Out-File (Join-Path $moduleUpdaterFolder 'STIGS\NEWSTIGS-$FileName.psm1') -Encoding default
    }

    #Write a message with the STIGs to verify
    if($ManVer) {
        $ManVer.ForEach({
            Write-Warning "Vuln_ID: $($_.Vuln_Id) was updated to Rule_ID: $($_.Rule_ID) and did not match the check text of the $($_.LegacyRule_ID). Please manually verify and update."
            [PSCustomObject]@{
                Vuln_ID = $_.Vuln_ID
                Rule_ID = $_.Rule_ID
                LegacyID = $_.Legacy_ID
                LegacyRule_ID = $_.LegacyRule_ID
                Benchmark = $_.Benchmark
            } | Export-Csv -NoTypeInformation -Path (Join-Path $moduleUpdaterFolder 'ManuallyVerify.csv') -Append
        })
    }

    #Checking for missed or orphaned STIGs
    $badVuln_ID = ($Oldckl | Where-Object {$_.Benchmark -match $ModuleType} | 
        Where-Object {($_.Vuln_ID -NotIn $Newckl.Vuln_ID) -and ($_.Vuln_ID -NotIn $ManVer.Vuln_ID) -and ($_.Vuln_ID -NotIn $ManVer.Legacy_ID)}).Vuln_ID
    $badRule_ID = ($Oldckl | Where-Object {$_.Benchmark -match $ModuleType} | 
        Where-Object {($_.Rule_ID -NotIn $Newckl.Rule_ID) -and ($_.Rule_ID -NotIn $ManVer.Rule_ID) -and ($_.Rule_ID -NotIn $ManVer.LegacyRule_ID)}).Rule_ID
            
    Write-Host "Checking for missed Vuln_IDs" -ForegroundColor Yellow
    $badVuln_ID.ForEach({
        if($module -match $_) {
            Write-Warning "Found Vuln_ID: $_ in module and it is no longer included in the newest version of the STIG."
            "Module;Benchmark: $ModuleType; Vuln_ID: $_" | Out-File -FilePath (Join-Path $moduleUpdaterFolder 'RemoveFromModules.txt') -Append
        } elseif($orgsettings -match $_) {
            Write-Warning "Found Vuln_ID: $_ in orgsettings and it is no longer included in the newest version of the STIG."
            "OrgSettings;Benchmark: $ModuleType; Vuln_ID: $_" | Out-File -FilePath (Join-Path $moduleUpdaterFolder 'RemoveFromModules.txt') -Append
        }
    })

    Write-Host "Checking for missed Rule_IDs" -ForegroundColor Yellow
    $badRule_ID.ForEach({
        if($module -match $_) {
            Write-Warning "Found Rule_ID: $_ in module and it is no longer included in the newest version of the STIG."
            "Module;Benchmark: $ModuleType; Rule_ID: $_" | Out-File -FilePath (Join-Path $moduleUpdaterFolder 'RemoveFromModules.txt') -Append
        } elseif($orgsettings -match $_) {
            Write-Warning "Found Rule_ID: $_ in orgsettings and it is no longer included in the newest version of the STIG."
            "OrgSettings;Benchmark: $ModuleType; Rule_ID: $_" | Out-File -FilePath (Join-Path $moduleUpdaterFolder 'RemoveFromModules.txt') -Append
        }
    })
}
Stop-Transcript -ErrorAction SilentlyContinue
Write-Host "Control Returned to the launcher."