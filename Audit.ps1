#Clears the screen
cls

#RECORDING TRANSCRIPT TO DUMP FILE
$CurrentDir = $PSScriptRoot

$ServerName = $env:computername
$DumpFilePath = "$CurrentDir\"+$ServerName+"-CONFIG_DUMP_$(get-date -Format yyyy-mm-dd_hh_mm_tt).txt"

Start-Transcript -Path $DumpFilePath -NoClobber

$Begin = (Get-Date).Minute

$ExecutionPolicy = Get-ExecutionPolicy

$Executionbeforescript = Get-ExecutionPolicy

$scriptExecution = "Unrestricted"

    If ($ExecutionPolicy -eq $ScriptExecution) 
        {  
            Write-Host 'Your PowerShell Script Execution Policy is set to' $ExecutionPolicy
            Write-Host
            Write-Host 'This policy should be set to RemoteSigned for the script to execute properly.' 
            Write-Host
            Write-Host 'This change will be reverted back to its original state after script execution is complete.' 
            Write-Host
            Write-Host 'Setting PowerShell Script Execution Policy to RemoteSigned automatically. Please Wait...'
            Start-Sleep -s 5
            
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -force
        
            $Executionduringscript = Get-ExecutionPolicy

            Write-Host
            Write-Host 'PowerShell Script Execution Policy is now set RemoteSigned'
            Start-Sleep -s 5
            
        }
    Else
        {
         Write-Host 'Your powershell script is already set to '$ExecutionPolicy. You can execute powershell script 
        }
 
 # Information about the BIOS
 Write-Host "        BIOS Information *********** "

get-WmiObject -Class CIM_BIOSElement |select-Object SMBIOSBIOSVersion, Manufacturer, SerialNumber, Version |Format-List
Start-Sleep -s 5


 #OS Info
 Write-Host "       2) Operating System Information ********* "
 Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version , CSName, OSArchitecture, ServicePackMajorVersion, WindowsDirectory , BootDevice
 Start-Sleep -s 5
 

 #Computer System
 Write-Host "       Computer System *********** "
 Get-WmiObject -Class Win32_OperatingSystem 
 Start-Sleep -s 5
 

#Information about UserAccount
Write-Host "        3) User Account ********** "

Get-LocalUser   |  Select *
Start-Sleep -s 5

Write-Host "        Checking for User Account Control**** "
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
Start-sleep -s 5
#Get-ChildItem env:/ -Recurse 

#Environment Variable
Write-Host "        4 ) Checking directories in PATH environment variable ********* "

Get-Item -Path Env:* | Select *
Start-Sleep -s 10


Write-Host "        5 ) Enumerating auto runs registry  ******** "
Get-CIMInstance -Class Win32_StartupCommand | select * | fl


 Write-Host "       Retrieving Acl for winlogon **** "
 Get-Acl C:\Windows\System32\winlogon.exe | Select *
 Start-Sleep -s 5
 

 Write-Host "       LSA***** "

 Get-Acl -path 'HKLM:\System\CurrentControlSet\Control\LSA' |Select * |fl
 
 Write-Host "       Server Pipe***** "

 Get-Acl -path 'HKLM:\System\CurrentControlSet\Control\SecurePipeServers'|Select * | fl

 Write-Host "       Knows DLLS******* "

 Get-Acl -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'| Select * | fl
 Start-Sleep -s 10

 Write-Host "       AllowedPATHS "

Get-Acl -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths' | Select * | fl
Start-Sleep -s 10

 #Process en cours
 Write-Host "       Running Process ******** "
Get-Process | Select ProcessName, Id | fl
Start-Sleep -s 10


#Information about installed package
Write-Host "        6 ) Installed Security products ******* "
Get-WmiObject -Namespace root\SecurityCenter2 -Class Antivirusproduct |Select * |fl

Start-Sleep -s 5


#Information about the firewall
Write-Host "        7 ) Firewall ******* "

Get-NetFirewallProfile | Select * | fl
Get-NetFirewallRule |measure |select count | fl

Write-Host "        Activate Firewall logging **** "

Write-Host  "       Set-NetFirewallProfile -LogBlocked True "
Set-NetFirewallProfile -LogBlocked True

#Check the ACL on the logging file 
Write-Host "        Check the ACL on the logging file ******"

Get-Acl -path "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" | Select * |fl

Start-Sleep -s 5


#AppLocker Status and Policies and checking device guard status
Write-Host "           8 ) AppLocker Status Policies and Checking device guard status "

Write-Host "AppLocker Status and Policies"

$Operating_System = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption

if ($Operating_System.Caption -eq "Microsoft Windows 10 Famille" -Or $Operating_System.Caption -eq "Microsoft Windows 10 Family" ){

    Write-Host "      As your System is a Microsoft Windows 10 Family , sorry but you can have th AppLocker Status and Policies "
    Write-Host 
    Write-Host "      Notice that on Windows 10 Pro you can use this command to have the AppLocker Status and policies :   Get-AppLockerPolicy -Local "

} else {
    Get-AppLockerPolicy -Local | Select * |fl
    
}


Write-Host "         Device Guard Status ****** "

Get-WmiObject -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |Select * |fl
Start-Sleep -s 10



# Enumerating exposed local filesystem shares. Start a quick scan on these shares
# Show the file extensions present in each share

Write-Host "       9 ) Enumerating exposed local filesystem ******* "
Get-SmbShare | ft
Write-Host "         Start the scan on exposed filesystem** "

$file_path = Get-SmbShare | Select Path

ForEach ($scan in $file_path){
    if ($scan.Path){
    Write-Host "     Start Quick Scan on " $scan.Path                                                                   #check if we don't have null has value for the path
    Start-MpScan -ScanPath $scan.Path -ScanType QuickScan

    Write-Host
    Write-Host "     File Extensions on " $scan.Path
    Get-ChildItem $scan.Path | select extension -Unique | ft
    
    }
}

Write-Host "        Scan on Exposed File completed **"

Start-Sleep -s 5 


#Checking BitLockerStatus on all volumes and permissions on NTFS drives 

Write-Host "        10 ) Check BitLocker Status on all volumes and NTFS permissions**********"
Get-BitLockerVolume | ft

Start-Sleep -s 5

Write-Host "        NTFS Permissions** "
Write-Host "        Please wait the complete installation of NTFSSecurity Module***"
Install-Module NTFSSecurity -Force
Start-Sleep -s 5

$BitLocker = Get-BitLockerVolume | Select MountPoint
ForEach ($Bit in $BitLocker){
    Get-NTFSAccess -Path $Bit.MountPoint | fl
}

Start-Sleep -s 10


#Certificated

Write-Host "         11 ) Enumerating Installed certificated*********"
Get-ChildItem Cert:\ -Recurse | sort Certificates | select * | fl
Start-Sleep -s 5


$Ends = (Get-Date).Minute

Write-Host "          12) Analyze complete ****"

$Time_Execution = ($Ends - $Begin)

Write-Host " This script takes " $Time_Execution minutes

If ($Executionbeforescript -eq $Executionduringscript) {


    Write-Host Script execution complete. Please Wait... 
    Write-Host
    Start-Sleep -s 5
    Write-Host All done. Have a good day.


} else { 
    
      Write-Host
    Write-Host Script execution complete. Please Wait... 
    Write-Host
    Start-Sleep -s 5
    Write-Host Reverting the PowerShell script execution policy to $Executionbeforescript 
    
        Start-Sleep -s 5
        Set-ExecutionPolicy -ExecutionPolicy $Executionbeforescript -force

    Write-Host
    Write-Host The PowerShell Script Execution Policy setting has been reverted back to $Executionbeforescript 
    Write-Host 
    Write-Host All done. Have a good day.
    Write-Host
}

#STOP RECORDING TRANSCRIPT
Stop-Transcript