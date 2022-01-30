function Global:Check-RegKeyValue {
    #This function returns the requested Registry Value at the provided Registry Key path
    #$regPath example: HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing Criteria
    #$regValue is the value of the provided Registry Key in $regPath
    #$EA is erroraction, and defaults to Continue (so you can provide SilentlyContinue in case you know it will error out)
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $regPath,

        [Parameter(Mandatory)]
        [string]
        $regValueName,

        [Parameter()]
        [string]
        $EA = "SilentlyContinue"
    )
    
    #Return the value of the specified Registry key's $regValueName
    try {
        return (Get-ItemProperty ("Registry::" + $regPath) -Name $regValueName -ErrorAction $EA | select -ExpandProperty $regValueName)
    } catch {
        Write-Host ($regpath + " - " + $regValueName + "`n" + $_)
    }
}

function Validate-OrgSettings { 
    #This function is a substitute for the PS7 test-json cmdlet with some extra stuff for neater outputs
    #TODO: Fix this... wow
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        $settings
    )

    $allowedstatusvalues=@('Open','NotAFinding','Not_Applicable')

    $return=@()
    $MFRs = $settings.MFRs | where {$_ -notmatch "^V-"} | %{$_ + " is not a valid MFR Vuln_ID"}
    $POAMS = $settings.POAMS | where {$_ -notmatch "^V-"} | %{$_ + " is not a valid POA&M Vuln_ID"}

    $entries = foreach ($Entry in $settings.Manual_Entries) {
                if ($Entry.Rule_ID -match "^SV-.*_rule$") {    #Rule ID is Valid, continue

                    if($Entry.Status -in $allowedstatusvalues) { #Status is valid, continue

                    } else {
                        $Entry.Vuln_ID + " has invalid status"
                    }
                } else {
                    $Entry.Vuln_ID + " has invalid rule"
                }
            }

    $return+=$MFRs +=$POAMS+=$entries

    Return $return
}

function Parse-STIGS {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [xml]$cklFile
    )

    $STIGS = $cklFile.CHECKLIST.stigs.iSTIG.vuln
    $stigArray=@()
@"
Vuln_Num
Rule_ID
Rule_Title
Check_Content
STIGRef
"@.split("`n") | ForEach-Object {
        New-Variable -Name ($_.trim() + "_index") -Value $STIGs[0].STIG_DATA.VULN_ATTRIBUTE.IndexOf($_.trim()) -Force
    }
    :main for ($STIG_index = 0; $STIG_index -lt $STIGs.count; $STIG_index++) {

        $Rule_ID = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_ID_Index]
        $Vuln_ID = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Vuln_Num_Index]
        $Rule_Title = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Rule_Title_Index]
        $Benchmark = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$STIGRef_Index]
        $Check_Content = $STIGs[$STIG_index].STIG_DATA.ATTRIBUTE_DATA[$Check_Content_Index]
        $stigArray+=[PSCustomObject]@{Vuln_ID=$Vuln_ID;Benchmark=$Benchmark;Rule_Title=$Rule_Title;Rule_ID=$Rule_ID;CheckText=$Check_Content}
    }

    return $stigArray
}
