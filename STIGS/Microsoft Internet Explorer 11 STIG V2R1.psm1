<#
Module Created by Michael Calabrese (1468714589)
Designed to be used with SCAPer script v5+

Microsoft Internet Explorer 11 Security Technical Implementation Guide :: Version 2, Release: 1 Benchmark Date: 27 Oct 2021
#>

#V-250540
#Turn off Encryption Support must be enabled.
Function SV-250540r804978_rule {
    #TLS 1.1 and 1.2 only
    #SSL 2.0 - 8
    #SSL 3.0 - 32
    #TLS 1.0 - 128
    #TLS 1.1 - 512
    #TLS 1.2 - 2048
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\" "SecureProtocols" "SilentlyContinue"
    if ($Value -eq "2048") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223015
#The Internet Explorer warning about certificate address mismatch must be enforced.
Function SV-223015r428597_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Turn on certificate address mismatch warning : Enabled
    $ValueName = "WarnOnBadCertRecving"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223016
#Check for publishers certificate revocation must be enforced.
Function SV-223016r428600_rule {
    #NA if SIPR
    if ($Global:IsNIPR) {
        $ValueName = "State"
        $Value = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "146432") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            } #0x23C00
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else {
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-223017
#The Download signed ActiveX controls property must be disallowed (Internet zone).
Function SV-223017r428603_rule {
    $ValueName = "1001"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223018
#The Download unsigned ActiveX controls property must be disallowed (Internet zone).
Function SV-223018r428606_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #Download unsigned ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box
    $ValueName = "1004"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223019
#The Initialize and script ActiveX controls not marked as safe property must be disallowed (Internet zone).
Function SV-223019r428609_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Initialize and script ActiveX controls not marked as safe' to 'Enabled', and select 'Disable' from the drop-down box.
    $ValueName = "1201"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46505
#Font downloads must be disallowed (Internet zone).
Function SV-59369r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow font downloads' to 'Enabled', and select 'Disable' from the drop-down box.
    $ValueName = "1604"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223020
#The Java permissions must be disallowed (Internet zone).
Function SV-223020r428612_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223021
#Accessing data sources across domains must be disallowed (Internet zone).
Function SV-223021r428615_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #"Access data sources across domains" will be set to "Enabled" and "Disable"
    $ValueName = "1406"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223022
#Functionality to drag and drop or copy and paste files must be disallowed (Internet zone).
Function SV-223022r428618_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow drag and drop or copy and paste files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1802"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223023
#Launching programs and files in IFRAME must be disallowed (Internet zone).
Function SV-223023r428621_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Launching applications and files in an IFRAME' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1804"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223024
#Navigating windows and frames across different domains must be disallowed (Internet zone).
Function SV-223024r428624_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Navigate windows and frames across different domains' to 'Enabled', and select 'Disable' from the drop-down box.
    $ValueName = "1607"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223025
#Userdata persistence must be disallowed (Internet zone).
Function SV-223025r428627_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Userdata persistence' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1606"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        } 
    }

#V-223026
#Clipboard operations via script must be disallowed (Internet zone).
Function SV-223026r428630_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow cut, copy or paste operations from the clipboard via script' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1407"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223027
#Logon options must be configured to prompt (Internet zone).
Function SV-223027r428633_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #"Logon options" to "Enabled", and select "Prompt for user name and password" from the drop-down box. 
    $ValueName = "1A00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 65536) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223028
#Java permissions must be configured with High Safety (Intranet zone).
Function SV-223028r428636_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Intranet Zone
    #"Java permissions" will be set to “Enabled” and "High Safety".
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 65536) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223030
#Java permissions must be configured with High Safety (Trusted Sites zone).
Function SV-223030r428642_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Trusted Sites Zone
    #"Java permissions" will be set to “Enabled” and "High Safety".
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 65536) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223032
#Dragging of content from different domains within a window must be disallowed (Internet zone).
Function SV-223032r428648_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone
    #'Enable dragging of content from different domains within a window' to 'Enabled', and select 'Disabled' from the drop-down box. 
    $ValueName = "2708"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 3) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223033
#Dragging of content from different domains across windows must be disallowed (Restricted Sites zone).
Function SV-223033r428651_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone
    #'Enable dragging of content from different domains across windows' to 'Enabled', and select 'Disabled' from the drop-down box.
    $ValueName = "2709"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 3) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223034
#Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer).
Function SV-223034r428654_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
    #“Internet Explorer Processes” must be “Enabled”. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 1) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223035
#Internet Explorer Processes Restrict ActiveX Install must be enforced (iexplore).
Function SV-223035r428657_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
    #“Internet Explorer Processes” must be “Enabled”. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 1) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223036
#Dragging of content from different domains within a window must be disallowed (Restricted Sites zone).
Function SV-223036r428660_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Restricted Sites Zone
    #'Enable dragging of content from different domains within a window' to 'Enabled', and select 'Disabled' from the drop-down box. 
    $ValueName = "2708"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq 3) {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223051
#The Download signed ActiveX controls property must be disallowed (Restricted Sites zone).
Function SV-223051r428705_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Download signed ActiveX controls' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1001"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223054
#The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone).
Function SV-223054r428714_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #"Download unsigned ActiveX controls" to "Enabled", and select "Disable" from the drop-down box.
    $ValueName = "1004"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223057
#The Initialize and script ActiveX controls not marked as safe property must be disallowed (Restricted Sites zone).
Function SV-223057r428723_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #'Initialize and script ActiveX controls not marked as safe' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1201"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223058
#ActiveX controls and plug-ins must be disallowed (Restricted Sites zone).
Function SV-223058r428726_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #'Run ActiveX controls and plugins' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1200"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223059
#ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone).
Function SV-223059r428729_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Script ActiveX controls marked safe for scripting' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1405"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223060
#File downloads must be disallowed (Restricted Sites zone).
Function SV-223060r428732_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1803"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-46585
#Font downloads must be disallowed (Restricted Sites zone).
Function SV-59449r1_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow font downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1604"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}}
    else {return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}}
    }

#V-223061
#Java permissions must be disallowed (Restricted Sites zone).
Function SV-223061r428735_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223062
#Accessing data sources across domains must be disallowed (Restricted Sites zone).
Function SV-223062r428738_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Access data sources across domains' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1406"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223063
#The Allow META REFRESH property must be disallowed (Restricted Sites zone).
Function SV-223063r428741_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow META REFRESH' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1608"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223064
#Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone).
Function SV-223064r428744_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow drag and drop or copy and paste files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1802"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223065
#Launching programs and files in IFRAME must be disallowed (Restricted Sites zone).
Function SV-223065r428747_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Launching applications and files in an IFRAME' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1804"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223066
#Navigating windows and frames across different domains must be disallowed (Restricted Sites zone).
Function SV-223066r428750_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Navigate windows and frames across different domains' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1607"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223067
#Userdata persistence must be disallowed (Restricted Sites zone).
Function SV-223067r428753_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Userdata persistence' to 'Enabled', and select 'Disable' from the drop-down box 
    $ValueName = "1606"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223068
#Active scripting must be disallowed (Restricted Sites Zone).
Function SV-223068r428756_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow active scripting' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1400"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223069
#Clipboard operations via script must be disallowed (Restricted Sites zone).
Function SV-223069r428759_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow cut, copy or paste operations from the clipboard via script' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1407"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223070
#Logon options must be configured and enforced (Restricted Sites zone).
Function SV-223070r428762_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Logon options' to 'Enabled', and select 'Anonymous logon' from the drop-down box. 
    $ValueName = "1A00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "196608") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223071
#Configuring History setting must be set to 40 days.
Function SV-223071r428765_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History
    #'Disable Configuring History' to 'Enabled', and enter '40' in 'Days to keep pages in History'. 
    $ValueName1 = "History"
    $Value1 = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Control Panel" -Name $ValueName1 | select -ExpandProperty $ValueName1
    $ValueName2 = "DaysToKeep"
    $Value2 = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History" -Name $ValueName2 | select -ExpandProperty $ValueName2
    if ($Value1 -eq "1" -and $Value2 -eq "40") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223072
#Internet Explorer must be set to disallow users to add/delete sites.
Function SV-223072r428768_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components
    #Internet Explorer "Security Zones: Do not allow users to add/delete sites" to "Enabled". 
    $ValueName = "Security_zones_map_edit"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName -EA SilentlyContinue | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223073
#Internet Explorer must be configured to disallow users to change policies.
Function SV-223073r428771_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components
    #Internet Explorer 'Security Zones: Do not allow users to change policies' to 'Enabled'. 
    $ValueName = "Security_options_edit"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName -EA SilentlyContinue | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223074
#Internet Explorer must be configured to use machine settings.
Function SV-223074r428774_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components
    #Internet Explorer 'Security Zones: Use only machine settings' to 'Enabled'. 
    $ValueName = "Security_HKLM_only"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}}
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223075
#Security checking features must be enforced.
Function SV-223075r428777_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
    #'Turn off the Security Settings Check feature' to 'Disabled'.
    $ValueName = "DisableSecuritySettingsCheck"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Security" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223076
#Software must be disallowed to run or install with invalid signatures.
Function SV-223076r428780_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
    #'Allow software to run or install even if the signature is invalid' to 'Disabled'. 
    $ValueName = "RunInvalidSignatures"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Download" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223078
#Checking for server certificate revocation must be enforced.
Function SV-223078r428786_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
    #'Check for server certificate revocation' to 'Enabled'. 
    $ValueName = "CertificateRevocation"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223079
#Checking for signatures on downloaded programs must be enforced.
Function SV-223079r428789_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Advanced Page
    #'Check for signatures on downloaded programs' to 'Enabled'. 
    $ValueName = "CheckExeSignatures"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Download" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "yes") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223080
#All network paths (UNCs) for Intranet sites must be disallowed.
Function SV-223080r428792_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #'Intranet Sites: Include all network paths (UNCs)' to 'Disabled'. 
    $ValueName = "UNCAsIntranet"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223081
#Script-initiated windows without size or position constraints must be disallowed (Internet zone).
Function SV-223081r428795_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow script-initiated windows without size or position constraints' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2102"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223082
#Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone).
Function SV-223082r428798_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow script-initiated windows without size or position constraints' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2102"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223083
#Scriptlets must be disallowed (Internet zone).
Function SV-223083r428801_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow Scriptlets' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1209"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223084
#Automatic prompting for file downloads must be disallowed (Internet zone).
Function SV-223084r428804_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Automatic prompting for file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2200"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223085
#Java permissions must be disallowed (Local Machine zone).
Function SV-223085r428807_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Local Machine Zone
    #"Java permissions" to "Enabled", and "Disable Java" selected from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223087
#Java permissions must be disallowed (Locked Down Local Machine zone).
Function SV-223087r428813_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Local Machine Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223088
#Java permissions must be disallowed (Locked Down Intranet zone).
Function SV-223088r428816_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Intranet Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223089
#Java permissions must be disallowed (Locked Down Trusted Sites zone).
Function SV-223089r428819_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Trusted Sites Zone
    #"Java permissions" to "Enabled", and select "Disable Java" from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223090
#Java permissions must be disallowed (Locked Down Restricted Sites zone).
Function SV-223090r428822_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Locked-Down Restricted Sites Zone
    #'Java permissions' to 'Enabled', and select 'Disable Java' from the drop-down box. 
    $ValueName = "1C00"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223091
#XAML files must be disallowed (Internet zone).
Function SV-223091r428825_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow loading of XAML files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2402"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223092
#XAML files must be disallowed (Restricted Sites zone).
Function SV-223092r428828_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow loading of XAML files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2402"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}}
    }

#V-223093
#Protected Mode must be enforced (Internet zone).
Function SV-223093r428831_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Turn on Protected Mode' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "2500"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223094
#Protected Mode must be enforced (Restricted Sites zone).
Function SV-223094r428834_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Turn on Protected Mode' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "2500"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223095
#Pop-up Blocker must be enforced (Internet zone).
Function SV-223095r428837_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Use Pop-up Blocker' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "1809"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223096
#Pop-up Blocker must be enforced (Restricted Sites zone).
Function SV-223096r428840_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Use Pop-up Blocker' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "1809"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
                
    }

#V-223097
#Websites in less privileged web content zones must be prevented from navigating into the Internet zone.
Function SV-223097r428843_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2101"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223098
#Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone.
Function SV-223098r428846_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Web sites in less privileged Web content zones can navigate into this zone' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2101"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223099
#Allow binary and script behaviors must be disallowed (Restricted Sites zone).
Function SV-223099r428849_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #"Allow binary and script behaviors" to "Enabled", and select "Disable" from the drop-down box. 
    $ValueName = "2000"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223100
#Automatic prompting for file downloads must be disallowed (Restricted Sites zone).
Function SV-223100r428852_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Automatic prompting for file downloads' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2200"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223101
#Internet Explorer Processes for MIME handling must be enforced. (Reserved)
Function SV-223101r428855_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223102
#Internet Explorer Processes for MIME handling must be enforced (Explorer).
Function SV-223102r428858_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223103
#Internet Explorer Processes for MIME handling must be enforced (iexplore).
Function SV-223103r428861_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Consistent Mime Handling
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223104
#Internet Explorer Processes for MIME sniffing must be enforced (Reserved).
Function SV-223104r428864_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223105
#Internet Explorer Processes for MIME sniffing must be enforced (Explorer).
Function SV-223105r428867_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223106
#Internet Explorer Processes for MIME sniffing must be enforced (iexplore).
Function SV-223106r428870_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Mime Sniffing Safety Feature
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223107
#Internet Explorer Processes for MK protocol must be enforced (Reserved).
Function SV-223107r428873_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
    #"Internet Explorer Processes" to "Enabled". 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223108
#Internet Explorer Processes for MK protocol must be enforced (Explorer).
Function SV-223108r428876_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
    #"Internet Explorer Processes" to "Enabled". 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223109
#Internet Explorer Processes for MK protocol must be enforced (iexplore).
Function SV-223109r428879_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> MK Protocol Security Restriction
    #"Internet Explorer Processes" to "Enabled". 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223110
#Internet Explorer Processes for Zone Elevation must be enforced (Reserved).
Function SV-223110r428882_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223111
#Internet Explorer Processes for Zone Elevation must be enforced (Explorer).
Function SV-223111r428885_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223112
#Internet Explorer Processes for Zone Elevation must be enforced (iexplore).
Function SV-223112r428888_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Protection From Zone Elevation
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223113
#Internet Explorer Processes for Restrict File Download must be enforced (Reserved).
Function SV-223113r428891_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict File Download
    #'Internet Explorer Processes' to 'Enabled'.
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223114
#Internet Explorer Processes for Restrict File Download must be enforced (Explorer).
Function SV-223114r428894_rule {
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223115
#Internet Explorer Processes for Restrict File Download must be enforced (iexplore).
Function SV-223115r428897_rule {
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223116
#Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved).
Function SV-223116r428900_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223117
#Internet Explorer Processes for restricting pop-up windows must be enforced (Explorer).
Function SV-223117r428903_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223118
#Internet Explorer Processes for restricting pop-up windows must be enforced (iexplore).
Function SV-223118r428906_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Scripted Window Security Restrictions
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223119
#.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Sites Zone).
Function SV-223119r428909_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2004"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if($Value -eq "3"){
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223120
#.NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone).
Function SV-223120r428912_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box.
    $ValueName = "2001"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223121
#Scripting of Java applets must be disallowed (Restricted Sites zone).
Function SV-223121r428915_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #"Scripting of Java applets" to "Enabled", and select "Disable" from the drop-down box. 
    $ValueName = "1402"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223122
#AutoComplete feature for forms must be disallowed.
Function SV-223122r428918_rule {
    #User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
    #'Disable AutoComplete for forms' to 'Enabled'. 
    $ValueName = "Use FormSuggest"
    $Value = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "no") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223123
#Crash Detection management must be enforced.
Function SV-223123r428921_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
    #'Turn off Crash Detection' to 'Enabled'.
    $ValueName = "NoCrashDetection"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223124
#Turn on the auto-complete feature for user names and passwords on forms must be disabled.
Function SV-223124r428924_rule {
    #User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer
    #"Turn on the auto-complete feature for user names and passwords on forms" to "Disabled". 
    $ValueName1 = "FormSuggest Passwords"
    $Value1 = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName1 | select -ExpandProperty $ValueName1
    $ValueName2 = "FormSuggest PW Ask"
    $Value2 = Get-ItemProperty -Path "Registry::HKCU\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName2 | select -ExpandProperty $ValueName2
    if ($Value1 -eq "no" -and $Value2 -eq "no") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223125
#Managing SmartScreen Filter use must be enforced.
Function SV-223125r428927_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
    #"Prevent Managing SmartScreen Filter" to "Enabled", and select "On" from the drop-down box. 
    if (!$Global:IsNIPR) {return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    $ValueName = "EnabledV9"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223126
#Browser must retain history on exit.
Function SV-223126r428930_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History
    #“Configure Delete Browsing History on exit” to “Disabled”.
    $ValueName = "ClearBrowsingHistoryOnExit"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223127
#Deleting websites that the user has visited must be disallowed.
Function SV-223127r428933_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History"
    #Prevent Deleting Web sites that the User has Visited" to "Enabled". 
    $ValueName = "CleanHistory"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223128
#InPrivate Browsing must be disallowed.
Function SV-223128r428936_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Privacy
    #'Turn off InPrivate Browsing' to 'Enabled'
    $ValueName = "EnableInPrivateBrowsing"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223129
#Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone).
Function SV-223129r428939_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow scripting of Internet Explorer WebBrowser controls' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1206"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223130
#When uploading files to a server, the local directory path must be excluded (Internet zone).
Function SV-223130r428942_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #"Include local path when user is uploading files to a server" to "Enabled", and select "Disable" from the drop-down box. 
    $ValueName = "160A"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223131
#Internet Explorer Processes for Notification Bars must be enforced (Reserved).
Function SV-223131r428945_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223132
#Security Warning for unsafe files must be set to prompt (Internet zone).
Function SV-223132r428948_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Show security warning for potentially unsafe files' to 'Enabled', and select 'Prompt' from the drop-down box. 
    $ValueName = "1806"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223133
#Internet Explorer Processes for Notification Bars must be enforced (Explorer).
Function SV-223133r428951_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
    #'Internet Explorer Processes' to 'Enabled'.
    $ValueName = "explorer.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223134
#ActiveX controls without prompt property must be used in approved domains only (Internet zone).
Function SV-223134r428954_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Allow only approved domains to use ActiveX controls without prompt' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "120b"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223135
#Internet Explorer Processes for Notification Bars must be enforced (iexplore).
Function SV-223135r428957_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features-> Notification Bar
    #'Internet Explorer Processes' to 'Enabled'.  
    $ValueName = "iexplore.exe"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223136
#Cross-Site Scripting Filter must be enforced (Internet zone).
Function SV-223136r428960_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone
    #'Turn on Cross-Site Scripting Filter' to 'Enabled', and select 'Enable' from the drop-down box.  
    $ValueName = "1409"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223137
#Scripting of Internet Explorer WebBrowser Control must be disallowed (Restricted Sites zone).
Function SV-223137r428963_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow scripting of Internet Explorer WebBrowser controls' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1206"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223138
#When uploading files to a server, the local directory path must be excluded (Restricted Sites zone).
Function SV-223138r428966_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Include local path when user is uploading files to a server' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "160A"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223139
#Security Warning for unsafe files must be disallowed (Restricted Sites zone).
Function SV-223139r428969_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Show security warning for potentially unsafe files' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1806"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223140
#ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone).
Function SV-223140r428972_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Allow only approved domains to use ActiveX controls without prompt' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "120b"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223141
#Cross-Site Scripting Filter property must be enforced (Restricted Sites zone).
Function SV-223141r428975_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone
    #'Turn on Cross-Site Scripting Filter' to 'Enabled', and select 'Enable' from the drop-down box. 
    $ValueName = "1409"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223142
#Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved).
Function SV-223142r428978_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Security Features -> Restrict ActiveX Install
    #'Internet Explorer Processes' to 'Enabled'. 
    $ValueName = "(Reserved)"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223143
#Status bar updates via script must be disallowed (Internet zone).
Function SV-223143r428981_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Internet Zone 'Allow updates to status bar via script' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2103"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223144
#.NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone).
Function SV-223144r428984_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Internet Zone 'Run .NET Framework-reliant components not signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2004"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223145
#.NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone).
Function SV-223145r428987_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Internet Zone 'Run .NET Framework-reliant components signed with Authenticode' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "2001"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223146
#Scriptlets must be disallowed (Restricted Sites zone).
Function SV-223146r428990_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Restricted Sites Zone 'Allow Scriptlets' to 'Enabled', and select 'Disable' from the drop-down box. 
    $ValueName = "1209"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223147
#Status bar updates via script must be disallowed (Restricted Sites zone).
Function SV-223147r428993_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page
    #Restricted Sites Zone "Allow updates to status bar via script" to "Enabled", and select "Disable" from the drop-down box. 
    $ValueName = "2103"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223148
#When Enhanced Protected Mode is enabled, ActiveX controls must be disallowed to run in Protected Mode.
Function SV-223148r428996_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page 
    #'Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled' to 'Enabled'. 
    $ValueName = "DisableEPMCompat"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223149
#Dragging of content from different domains across windows must be disallowed (Internet zone).
Function SV-223149r428999_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Security Page-> Internet Zone 
    #"Enable dragging of content from different domains across windows" to "Enabled", and select "Disabled". 
    $ValueName = "2709"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223150
#Enhanced Protected Mode functionality must be enforced.
Function SV-223150r429002_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel-> Advanced Page
    #"Turn on Enhanced Protected Mode" to "Enabled". 
    $ValueName = "Isolation"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "PMEM") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223077
#The 64-bit tab processes, when running in Enhanced Protected Mode on 64-bit versions of Windows, must be turned on.
Function SV-223077r428783_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Advanced Page 
    #'Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows' to 'Enabled'. 
    $ValueName = "Isolation64Bit"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Main" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223037
#Anti-Malware programs against ActiveX controls must be run for the Internet zone.
Function SV-223037r428663_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Internet Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223029
#Anti-Malware programs against ActiveX controls must be run for the Intranet zone.
Function SV-223029r428639_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Intranet Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223086
#Anti-Malware programs against ActiveX controls must be run for the Local Machine zone.
Function SV-223086r428810_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Local Machine Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223038
#Anti-Malware programs against ActiveX controls must be run for the Restricted Sites zone.
Function SV-223038r428666_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223031
#Anti-Malware programs against ActiveX controls must be run for the Trusted Sites zone.
Function SV-223031r428645_rule {
    #Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer-> Internet Control Panel -> Security Page -> Restricted Sites Zone 
    #'Don't run antimalware programs against ActiveX controls' to 'Enabled' and select 'Disable' in the drop-down box. 
    $ValueName = "270C"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223039
#Prevent bypassing SmartScreen Filter warnings must be enabled.
Function SV-223039r428669_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
    #”Prevent bypassing SmartScreen Filter warnings” to ”Enabled”. 
    if($Global:IsNIPR -eq $false){return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else{
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -regValueName "PreventOverride"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-223040
#Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet must be enabled.
Function SV-223040r428672_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
    #”Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet” to ”Enabled”. 
    if($Global:IsNIPR -eq $false){return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}}
    else{
        $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -regValueName "PreventOverrideAppRepUnknown"
        if ($Value -eq "1") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    }

#V-223041
#Prevent per-user installation of ActiveX controls must be enabled.
Function SV-223041r428675_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer
    #”Prevent per-user installation of ActiveX controls” to ”Enabled”. 
    $ValueName = "BlockNonAdminActiveXInstall"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223042
#Prevent ignoring certificate errors option must be enabled.
Function SV-223042r428678_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel
    #”Prevent ignoring certificate errors” to ”Enabled”. 
    $Value = Check-RegKeyValue "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -regValueName "PreventIgnoreCertErrors"
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223043
#Turn on SmartScreen Filter scan option for the Internet Zone must be enabled.
Function SV-223043r428681_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone
    #”Turn on SmartScreen Filter scan” to ”Enabled”, and select ”Enable” from the drop-down box. 
    $ValueName = "2301"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223044
#Turn on SmartScreen Filter scan option for the Restricted Sites Zone must be enabled.
Function SV-223044r428684_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
    #”Turn on SmartScreen Filter scan” to ”Enabled”, and select ”Enable” from the drop-down box. 
    $ValueName = "2301"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223045
#The Initialize and script ActiveX controls not marked as safe must be disallowed (Intranet Zone).
Function SV-223045r428687_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
    #”Initialize and script ActiveX controls not marked as safe” to ”Enabled”, and select ”Disable” from the drop-down box. 
    $ValueName = "1201"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223046
#The Initialize and script ActiveX controls not marked as safe must be disallowed (Trusted Sites Zone).
Function SV-223046r428690_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
    #”Initialize and script ActiveX controls not marked as safe” to ”Enabled”, and select ”Disable” from the drop-down box. 
    $ValueName = "1201"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "3") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-250541
#Allow Fallback to SSL 3.0 (Internet Explorer) must be disabled.
Function SV-250541r799949_rule {
    #Computer Configuration >> Administrative Templates >> Internet Explorer >> Security Features
    #"Allow fallback to SSL 3.0 (Internet Explorer)" to "Enabled", and select "No Sites" from the drop-down box. 
    $ValueName = "SecureProtocols"
    $Value = Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "2688") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }
#V-223048
#Run once selection for running outdated ActiveX controls must be disabled.
Function SV-223048r428696_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management
    #"Remove the Run this time button for outdated ActiveX controls in IE" to "Enabled". 
    $ValueName = "RunThisTimeEnabled"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "0") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223049
#Enabling outdated ActiveX controls for Internet Explorer must be blocked.
Function SV-223049r428699_rule {
    #(User Configuration? >>) Administrative Templates >> Windows Components >> Internet Explorer >> Security Features >> Add-on Management
    #"Turn off blocking of outdated ActiveX controls for IE" to "Disabled". 
    $ValueName = "VersionCheckEnabled"
    $Value = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext" -Name $ValueName | select -ExpandProperty $ValueName
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }

#V-223050
#Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Internet Zone.
Function SV-223050r428702_rule {
    #Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Intranet Zone
    #"Allow only approved domains to use the TDC ActiveX control" to "Enabled". 
    if($Global:OS -eq "Microsoft Windows Server 2016 Standard"){
        $ValueName = "120c"
        $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "3") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-223052
#Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Restricted Sites Zone.
Function SV-223052r428708_rule {
    #Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
    #"Allow only approved domains to use the TDC ActiveX control" to "Enabled". 
    if($Global:OS -eq "Microsoft Windows Server 2016 Standard"){
        $ValueName = "120c"
        $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "3") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-223053
#VBScript must not be allowed to run in Internet Explorer (Internet zone).
Function SV-223053r428711_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone
    #"Allow VBScript to run in Internet Explorer" to "Enabled" and select "Disable" from the drop-down box. 
    if($Global:OS -eq "Microsoft Windows 10 Enterprise"){
        $ValueName = "140C"
        $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "3") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-223055
#VBScript must not be allowed to run in Internet Explorer (Restricted Sites zone).
Function SV-223055r428717_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Restricted Sites Zone
    #"Allow VBScript to run in Internet Explorer" to "Enabled" and select "Disable" from the drop-down box. 
    if($Global:OS -eq "Microsoft Windows 10 Enterprise"){
        $ValueName = "140C"
        $Value = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" -Name $ValueName | select -ExpandProperty $ValueName
        if ($Value -eq "3") {
            return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
            }
        else {
            return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
            }
        }
    else{
        return [pscustomobject]@{Status='Not_Applicable';Comment='';Finding_Details=''}
        }
    }

#V-223056
#Internet Explorer Development Tools Must Be Disabled.
Function SV-223056r428720_rule {
    #Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Toolbars
    #“Turn off Developer Tools” must be “Enabled”.
    $Value = Check-RegKeyValue "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\IEDevTools" -regValueName "Disabled" -EA SilentlyContinue
    if ($Value -eq "1") {
        return [pscustomobject]@{Status='NotAFinding';Comment='';Finding_Details=''}
        }
    else {
        return [pscustomobject]@{Status='Open';Comment='';Finding_Details=''}
        }
    }
