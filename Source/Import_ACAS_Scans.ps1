#Requires -Version 5.0
<#
.SYNOPSIS
  Simple script to convert ACAS SCAP scans to a STIG checklist.
.DESCRIPTION
  Works through a STIG checklist and checks if the ACAS results have the same Vuln_Id.
  Actually in use by DISA CCRI inspectors. Pretty proud of that.
.INPUTS
  You will need to provide the checklist and ACAS Scans.
.OUTPUTS
  Log file named Import_ACAS_Scans.log stored in the Logs folder at the root of the SCAPer tool.
  STIG checklist with ACAS results populated.
.NOTES
  Version:        1.1
  Author:         Michael Calabrese
  Creation Date:  Unknown date in 2020
  Edit Date:      1/30/2022
  Purpose/Change: Updated to work with SCAPer Launcher
  ToDo List:
    - 
  
#>

#Initialize
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
$desktopDir = [Environment]::GetFolderPath('Desktop')

#Start logging, this is going to help in the long run
Start-Transcript (Join-Path $logFolder 'Import_ACAS_Scans.log') -Force | Out-Null

#Prompt for New STIG Checklist
$cklfile = New-Object System.Windows.Forms.OpenFileDialog
$cklfile.Filter = "Checklist | *.ckl"
$cklfile.Title = "Select checklist file to import."
$cklfile.InitialDirectory = $checklistFolder
[Void]$cklfile.ShowDialog()

if([bool]$cklfile.FileName) {
    Write-Host "Imported $($cklfile.FileName) as Checklist." -ForegroundColor Cyan
    $checklist = Get-Content $cklfile.FileName
} else {
    #if no checklist selected exit
    Continue
}

#This is the location of the ACAS SCAP results
$ACAS_ResultsFile = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
    InitialDirectory = [Environment]::GetFolderPath('Desktop')
    Filter = 'Scan Results (*.csv)|*.csv'
    Title = "Select scan results file to import"
}
[Void]$ACAS_ResultsFile.ShowDialog()

if([bool]$ACAS_ResultsFile.FileName) {
    Write-Host "Imported $($ACAS_ResultsFile.FileName) as Scan Results." -ForegroundColor Cyan
    $resultFileName = (Split-Path $ACAS_ResultsFile.FileName -Leaf)
    $ACAS_Results = Import-Csv $ACAS_ResultsFile.FileName
} else {
    #if no results selected exit
    Continue
}

#Creates variables to parse the XML file (thanks Chris)
$STIGS = $checklist.CHECKLIST.stigs.iSTIG.vuln

@"
Vuln_Num
Group_Title
Rule_ID
Rule_Title
Rule_Ver
Weight
Fix_Text
STIGRef
"@.split("`n") | foreach {
    New-Variable -Name ($_.trim() + "_index") -Value $STIGs[0].STIG_DATA.VULN_ATTRIBUTE.IndexOf($_.trim()) -Force
    }


#This part gets the acas results and puts them in the checklist
for ($STIG_index = 0; $STIG_index -lt $STIGs.count; $STIG_index++) {
    #Grab the vuln_Id from the stig attribute_data
    [string]$vulnNumber = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]

    Write-Host "Checking Vuln Number: $vulnNumber"

    #Match the vuln to the ACAS scan
    $vuln = $ACAS_Results | Where-Object {$_.vulns -eq $vulnNumber}

    if(!($null -eq $vuln)) {
        Switch($vuln.Status) {
            'NotAFinding' {
                $ActualStatus = "NotAFinding"
            }
            'Finding' {
                $ActualStatus = "Open"
            }
        }

        if ($ActualStatus -ne $null) {
            $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].STATUS = $ActualStatus
            $checklist.CHECKLIST.stigs.iSTIG.vuln[$STIG_index].FINDING_DETAILS = "Imported from ACAS Scan: $resultFileName"
        }
    }
    #reset our flag
    Remove-Variable ActualStatus,vuln -EA SilentlyContinue   
}

#Save file to desktop
$fileName = $cklfile.FileName.TrimEnd(".ckl")+".new.ckl"
Out-File -InputObject $checklist.Innerxml -FilePath (Join-Path $desktopDir $fileName) -Encoding default

Write-Host ("Saved to: " + (Join-Path $desktopDir $fileName))
Write-Host "Control Returned to the launcher."