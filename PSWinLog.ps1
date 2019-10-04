[Console]::OutputEncoding=[Text.Encoding]::Unicode

# Security Check
Function Check-Admin
{
    if (!([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
    write-host "No, I wont make you a sandwich. https://xkcd.com/149/"
    exit 1
    }
}

# Subin ACL
Function Allow-EventLog($user, $permission)
{
# https://social.technet.microsoft.com/wiki/contents/articles/51625.subinacl-a-complete-solution-to-configure-security-permission.aspx
Write-Host "Allowing user $user to access Event Log with permission $permission."
#cd ${PSScriptRoot}
./subinacl /keyreg HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\ /grant=${user}=${permission}
./subinacl /keyreg HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security /grant=${user}=${permission}
./subinacl /keyreg HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application /grant=${user}=${permission}
}

#File Check
Function Check-File-Exits($path)
{
    if (!(Test-Path $path -pathType Leaf))
	{
    write-host "$path Not Found. Exiting."
    exit 1
    }
}

Function Get-IfService ($name)
{
try
  {
  $result = Get-Service $name -ErrorAction Stop
  Write-Host "Service $name Found"
  return $true
  }
catch
  {
  Write-Host "Service $name Not Found"
  return $false
  }
}

#Service update user
Function Set-Service-User ($serviceName, $UserName, $Password)
{
$svcD=gwmi win32_service -filter "name='$serviceName'" 
$StopStatus = $svcD.StopService() 
If ($StopStatus.ReturnValue -eq "0") # validating status - http://msdn.microsoft.com/en-us/library/aa393673(v=vs.85).aspx 
    {write-host "$serviceName Service Stopped Successfully"} 
$ChangeStatus = $svcD.change($null,$null,$null,$null,$null,$null,$UserName,$Password,$null,$null,$null) 
If ($ChangeStatus.ReturnValue -eq "0")  
    {write-host "$serviceName Sucessfully Changed User Name to $UserName"} 
$StartStatus = $svcD.StartService() 
If ($ChangeStatus.ReturnValue -eq "0")  
    {write-host "$serviceName Service Started Successfully"} 
}


# Generate a Temporary - Pseudo Random Password 
Function Get-Pwd
{
    $pwd = -join(35..38 + 40..126|%{[char]$_}|Get-Random -C 13) + -join(48..57|%{[char]$_}|Get-Random -C 1)
    Write-Host "Password:" $pwd 
    return $pwd
}

#MAIN
#####

#Get IIS Args
$App = ""
if (($args.Length -eq 0) -or ($args.Length -gt 2))
{
  write-Host "PSWinlog.ps1 [AppPool] SysLogIP"
  exit(1);
  #$App = "Dev"
  #$SysLogIP = "127.0.0.1"
}
if ($args.Length -eq 1)
{
  $App = $null
  $SysLogIP = $args[0]
}
else
{
  $App = $args[0]
  $SysLogIP = $args[1]
}


Check-Admin

Check-File-Exits("sysmon.exe")

Check-File-Exits("sysmonconfig-export.xml")

Check-File-Exits("nxlog-ce-2.10.2150.msi")

<#
$VarHT = @{
AddSysMon = 1;
AddIISLog = 1;
AddIISFileAudit = 1;
AddLoginAudit = 1;
AddPowerShellAudit = 1;
AddProcessAudit = 0;
AddWinFWAudit = 1;
AddWinDefenderAudit = 1;
AddTimeChangeAudit = 1;
AddTaskScheduleAudit = 1 ;
AddRegistryPersistAudit = 1;
AddRegistrySystemAudit = 1;
AddRegistryForensicsAudit = 1;
AddDomainControllerAudit = 1}

ForEach ($v in $varHT.Keys)
{
   Write-Host($v.PadRight(25,' ') + ":" + $varHT[$v])
}
#>

if (!(Get-IfService("sysmon")))
{
  ##Install sysmon
  ./sysmon.exe -accepteula -i sysmonconfig-export.xml
}
else
{
  Write-Host "SysLog Previously Installed"
}

##Create svc-nxlog user
$pwd = Get-Pwd

$user = "svc_nxlog"
$userTest = Get-LocalUser $user -ErrorAction Ignore
if ($userTest -eq $null)
{
    Write-Host "Creating NXLog User $user"
    
    #Add User
    $secureString = ConvertTo-SecureString $pwd -AsPlainText -Force
    New-LocalUser $user -Password $secureString -FullName "nxlog Service" -Description "nxlog Service" -AccountNeverExpires
}
else
{
    #Update user password
    $secureString = ConvertTo-SecureString $pwd -AsPlainText -Force
    Set-LocalUser $user -Password $secureString -FullName "nxlog Service" -Description "nxlog Service" -AccountNeverExpires
   
    Write-Host "User $user Exists. Passwords Updated." -ForegroundColor Yellow
}

#Write Access to EventLog.
Allow-EventLog $user "R"

##Install nxlog
Write-Host "Install nxlog" 
msiexec /i nxlog-ce-2.10.2150.msi /quiet /qn /norestart /log nslog-install.log

##Run Service as svc-nxlog

for ($i=0; $i -lt 3; $i++)
{
    if (Get-IfService("nxlog") -eq $true)
    {
        $i = 3;
        continue;
    }
}

Write-Host "Create service user"
Set-Service-User nxlog svc_nxlog 

##Add nxlog.conf
if (!(Test-Path -Path ${Env:ProgramFiles(x86)}\nxlog))
{
    Write-Host "${Env:ProgramFiles(x86)}\nxlog does not Exist. Exiting."
    Exit 1
}


((Get-Content -path .\nxlog.conf.template -Raw) -replace '<%SYSLOGIP%>',$SysLogIP) | Set-Content -Path .\nxlog.conf
copy-item nxlog.conf ${Env:ProgramFiles(x86)}\nxlog\conf\ 


#PS WinEvt Policy/Reg
Write-Host "Importing PSAuditing.reg"
reg import /f PSAuditing.reg *>&1 | out-null

if ($App -eq $null)
{
#Remove IIS Conf reference
((Get-Content -path .\nxlog.conf -Raw) -replace 'include %CONFDIR%\\iis.conf','') | Set-Content -Path .\nxlog.conf
copy-item nxlog.conf ${Env:ProgramFiles(x86)}\nxlog\conf\ 
}
else
{

    Write-Host "Building IIS Logging for $App"

    ##Add nxlog iis.conf
    Write-Host "IIS Logging Setup" 
    Import-Module WebAdministration

    #Check IIS Log to write to 
    $WebLog = ""
    foreach($WebSite in $(get-website))
        {
        if ($WebSite.name -eq $App)
            {
            #Add Custom Log Entries
            $logFile="$($WebSite.logFile.directory)\w3svc$($WebSite.id)".replace("%SystemDrive%",$env:SystemDrive)
            Write-host "$($WebSite.name) [$logfile]"
            if ($WebLog -ne "" -and ($WebLog -ne $WebSite.logFile.directory))
             {
              throw "$WebLog does not equal $($WebSite.logFile.directory). Common log folder required for NXLog"
             }
             $WebLog = $WebSite.logFile.directory

             #Set Log Feilds
             $WebSiteName = $WebSite.name
             Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name=`"$WebSiteName`"]/LogFile" -Name LogExtFileFlags -Value "Date,Time,ClientIP,UserName,ServerIP,ServerPort,Method,UriStem,UriQuery,HttpStatus,UserAgent"
            } 
        }
    #Replace Log Locations 
    $WebLog = $WebLog -replace "%SystemDrive%",$env:SystemDrive
    Write-host " Website Logs Set to $WebLog"
    ((Get-Content -path .\iis.conf.template -Raw) -replace '<%IIS_LOGS%>',$WebLog) | Set-Content -Path .\iis.conf
    copy-item iis.conf ${Env:ProgramFiles(x86)}\nxlog\conf\ 

    #Add Custom Log Feild Data
    $logsFields = Get-ItemProperty IIS:\Sites\$App -name logfile.customFields.collection
    if (($logsFields | where logfieldName -Contains "CorrelationId" ) -eq $null)
    {
      Write-Host "Adding "CorrelationId" Logging to $App"
      New-ItemProperty IIS:\Sites\$App -name logfile.customFields.collection -value @{logFieldName='CorrelationId';sourceType='RequestHeader';sourceName='CORRELATION-ID'}
    }
    else
    {
      Write-Host "CorrelationId Logging exists in $App"
    }
    if (($logsFields | where logfieldName -Contains "IncapReqId" ) -eq $null)
    {
      Write-Host "Adding "CorrelationId" Logging to $App"
      New-ItemProperty IIS:\Sites\$App -name logfile.customFields.collection -value @{logFieldName='IncapReqId';sourceType='RequestHeader';sourceName='INCAP-REQ-ID'}
    }
    else
    {
      Write-Host "IncapReqId Logging exists in $App"
    }
}

##Add nxlog audit.conf

#File Audit Policy

#Add File locations to Obj Audit

#Registry location to Obj Audit

##Add nxlog service.conf

#Add Win FW evt

#Add Task Scheduler History (Audit)
#https://stackoverflow.com/questions/23227964/how-can-i-enable-all-tasks-history-in-powershell
$logName = 'Microsoft-Windows-TaskScheduler/Operational'
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.IsEnabled=$true
$log.SaveChanges()

Write-Host "Checking nxlog.log for Startup Success"
restart-service nxlog
Start-Sleep -Milliseconds 2500
Get-Content 'C:\Program Files (x86)\nxlog\data\nxlog.log' -Tail 2 | where {$_ -Match "Started"} | Foreach{ Write-Host -ForegroundColor Green $_; exit(0)} 
Get-Content 'C:\Program Files (x86)\nxlog\data\nxlog.log' -Tail 2 | where {$_ -NotMatch "Started"} | Foreach{ Write-Error -Message $_; exit(1)} 