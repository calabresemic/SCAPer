# SCAPer

Original framework by Chris Steele (1456084571)
3.0+ by SSgt Michael Calabrese (1468714589)

This script will automate STIG checking, no configuration changes will be made. This script will take the baseline checklist file, edit it, and export a new one. Each STIG check is based on the Rule_ID of the listed vulnerability (Since the same vuln ID is reused across OS's and when DISA updated the STIG details). If any items are still marked as Not reviewed, then its possible a new version of the STIG is being checked than what was coded.

1.  Log on the server you plan on STIGing 
2.  Copy the SCAPER Script folder onto the server you are logged in to.
3.  Open the folder and right click on the script file and select “Run with PowerShell”.
4.  Once the SCAPER Script is finished it will have created a new checklist, save the new checklist into the appropriate checklist folder in the share drive. 
5.   Open up STIGViewer with the checklist you saved from step 4 and go through and check for any opens without comments and any non-reviewed vulnerabilities
6.  To open up a checklist on STIGViewer you must go to Checklist tab in the left hand corner and click “Open Checklist From File” and open the checklist made from step 4
7.  If any opens without comments or any non-reviewed vulnerabilities are found they must be manually reviewed. 
8.  Once completed save the checklist and you are finished. 
9.  Repeat steps 1 through 7 for the rest of the servers you are STIGing.
