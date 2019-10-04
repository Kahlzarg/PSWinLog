# PSWinLog Script



## Usage

./pswinlogps1 [IIS-Site-Name] Syslog-Destination-Ip

IIS-Site-Name: Optional. Add IIS Setup for nxlog

Syslog-Destination-Ip: Set for 127.0.0.1 for local testing with Visual Syslog or similar.

## Prerequisites:

To be placed in the script folder

### Nxlog

Update filename in script for newer versions

nxlog-ce-2.10.2150.msi

https://nxlog.co/products/nxlog-community-edition/download

### SubInAcl

Windows Service Permissions

subinacl.exe

https://www.microsoft.com/en-au/download/details.aspx?id=23510

### Sysmon

For process monitoring

Sysmon.exe



# References

### Windows Event Logs



**Security** Events must be set to 500MB, rotating, on all systems.



![event-rotation](\img\event-rotation.png)

### Event Logs 

| Event ID                                                     | Event Name                                                   | GPO to Enable                                                | How to Trigger/Test                                    |
| :----------------------------------------------------------- | :----------------------------------------------------------- | :----------------------------------------------------------- | :----------------------------------------------------- |
|                                                              |                                                              | Local Users                                                  |                                                        |
| 4798                                                         | A user's local group membership was enumerated               |                                                              | Account and Group Enumeration                          |
| 4799                                                         | A security-enabled local group membership was enumerated     |                                                              | Account and Group Enumeration                          |
|                                                              |                                                              | Local & AD Users                                             |                                                        |
| 4780                                                         | The ACL was set on accounts which are members of administrators groups |                                                              | AdminSDHolder                                          |
| 4756                                                         | Member added to the security-enabled universal group         |                                                              | Alert                                                  |
| 4625                                                         | Account Lockout                                              |                                                              | Possible brute force                                   |
| 4624                                                         | Account Logon                                                |                                                              | Kekeo / Silver Ticket / Golden Ticket. PYKEK MS14-068  |
| 4625                                                         | An account failed to log on                                  | Computer Configuration<br /> > Policies<br /> > Windows Settings<br /> > Security Settings<br /> > Advanced Audit Configuration<br /> > Login/LogoffAudit Login (+Success +Failure) |                                                        |
| 4672                                                         | Admin Logon                                                  |                                                              | Kekeo / Silver Ticket / Golden Ticket. PYKEK MS14-068  |
| 4634                                                         | Account Logoff                                               |                                                              | Silver Ticket                                          |
| 4648                                                         | A logon was attempted using explicit credentials.            |                                                              | Mimikatz / PTH                                         |
| 4624                                                         | An account was successfully logged on.                       |                                                              | Mimikatz / PTH                                         |
|                                                              |                                                              | Kerberos                                                     |                                                        |
| Security4768                                                 | A Kerberos authentication ticket (TGT) was requested.        |                                                              | Kekeo / Mimikatz / PTH                                 |
| Security4769                                                 | A Kerberos service ticket (TGS) was requested.               |                                                              | Mimikatz / PTH. Someone tried to reuse Kerberos ticket |
| Security4732                                                 | Someone tried to reuse Kerberos ticket                       |                                                              |                                                        |
|                                                              |                                                              | Powershell                                                   |                                                        |
| Microsoft-Windows-PowerShell/Operational4103                 | Script Block Logging                                         | Administrative Templates<br /> > Windows Components<br /> > Windows PowerShellTurn on Powershell Script Block Logging<br />OR<br />HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows<br />\PowerShell\ScriptBlockLoggingEnableScriptBlockLogging = 1 | Powershell Script & Deobfuscated commands              |
| Microsoft-Windows-PowerShell/Operational4103                 | Module Logging                                               | Administrative Templates > Windows Components > Windows PowerShell.<br />Turn on Module LoggingIn the “Options” pane, click the button to show Module Name.<br />In the Module Names window, enter ***** to record all modules.<br />Click “OK” in the “Module Names” Window.<br />Click “OK” in the “Module Logging” Window.<br />OR  <br />HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft<br />\Windows\PowerShell\ModuleLoggingEnableModuleLogging = 1<br />HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\<br />Windows<br />\PowerShell\ModuleLogging \ModuleNames* = * | Module & Pipeline Execution                            |
| 4104                                                         | Remote PowerShell                                            |                                                              |                                                        |
| Windows Powershell800                                        |                                                              | Administrative Templates > Windows Components > Windows PowerShell.<br />Turn on Powershell transcription<br />OR  <br />HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\ \Windows\PowerShell\TranscriptionEnableTranscripting = 1 | Transcription                                          |
|                                                              |                                                              | Process Auditing                                             |                                                        |
| Security4688                                                 | A process has started                                        | May generate excess noise on top of Sysmon.High-Risk Systems Only.<br />Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking | Command Line Tracking. Skeleton Keys                   |
|                                                              | Command Line Process Auditing                                | Command-line auditing means any commands entered on the server will appear in logs. <br />This may need to be disabled in some cases, where passwords or keys are entered at the command line.<br />Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed TrackingANDAdministrative Templates\System\Audit Process CreationORHKLM\Software\Microsoft\Windows<br />\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1 |                                                        |
| Security4689                                                 | A process has exited                                         |                                                              | Skeleton Keys                                          |
|                                                              |                                                              | DC Shadow                                                    |                                                        |
| 4662                                                         | An operation was performed on an object                      | Reports on every interaction with an AD Object. Very noisy   | DCSync                                                 |
| 4742                                                         | A computer account was changed                               |                                                              | DCShadow                                               |
| 5137                                                         | A directory service object was created                       |                                                              | DCShadow                                               |
| 5141                                                         | A directory service object was deleted                       |                                                              | DCShadow                                               |
| 4929                                                         | An Active Directory replica source naming context was removed |                                                              | DCShadow                                               |
|                                                              |                                                              | Object (File & Registry) Auditing                            |                                                        |
| Security4719                                                 | Audit Policy Changed                                         |                                                              |                                                        |
| Security4907                                                 | Auditing Settings on Object Changed                          |                                                              | Adjust auditing security settings in file              |
| Security4660                                                 | An Object Was Deleted                                        | Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Object Access<br />Audit File Share |                                                        |
| Security4660                                                 |                                                              |                                                              |                                                        |
| Security4663                                                 | An attempt was made to access an object                      |                                                              |                                                        |
| Security4657                                                 | Registry key Modified                                        | Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Object Access<br />Audit Registry (+Success +Failure) |                                                        |
| Security4657                                                 | Registry Global Object Access Auditing                       | Global registry modification is excessively noisy Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Global Object Access Auditing<br />Registry |                                                        |
|                                                              |                                                              | Services & Setup                                             |                                                        |
| Security4616                                                 | System time changed. Could have done to alter logs by changing the timeline. |                                                              |                                                        |
| Security4697                                                 | Service is being installed in the system                     |                                                              | Map with CR                                            |
| Setup*                                                       |                                                              |                                                              |                                                        |
|                                                              |                                                              | Windows Firewall                                             |                                                        |
| Security5025                                                 | Windows firewall stopped.                                    |                                                              |                                                        |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall2004 | A rule has been added to the Windows Defender Firewall exception list |                                                              | Add Rule                                               |
| Microsoft-Windows-Windows Firewall With Advanced Security/Firewall2006 | A rule has been deleted in the Windows Defender Firewall exception list. |                                                              | Delete Rule                                            |
|                                                              |                                                              | Sysmon                                                       |                                                        |
| Microsoft-Windows-Sysmon/Operational                         | *                                                            | SuppressEventID=4689 (Process Existing)<br />EventID=5158 (Port Bind)<br />EventID=5440<br />EventID=5444 |                                                        |
|                                                              |                                                              | Task Scheduler                                               |                                                        |
| Microsoft-Windows-TaskScheduler/Operational                  | *                                                            |                                                              |                                                        |
| Security4702                                                 | A scheduled task was updated                                 |                                                              |                                                        |
|                                                              |                                                              | Windows Defender                                             |                                                        |
| Microsoft-Windows-Windows Defender/Operational1116           | *                                                            |                                                              |                                                        |
|                                                              |                                                              |                                                              |                                                        |

## Event Viewer Tasks

- Enable Login/Logoff Audit
- Enable PowerShell Audit
- Create File Audit Entries
- Crate Registry Audit Entries
- Install Sysmon as Service
- Enable Task Scheduler History

## Windows Registry Locations

| Source               | IoC         | Keys                                                         |
| :------------------- | :---------- | :----------------------------------------------------------- |
|                      | Persistence | HKLM\Software\Microsoft\Windows\CurrentVersion\Run HKCU\Software\Microsoft\Windows\CurrentVersion\Run HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce |
| LSA & Forensics      |             | HKLM\Sam HKLM\Security HKLM\System                           |
| AlienVault USM OSSEC |             | HKLM\Software\Classes\batfileHKLM\Software\Classes\cmdfileHKLM\Software\Classes\comfileHKLM\Software\Classes\exefileHKLM\Software\Classes\piffileHKLM\Software\Classes\AllFilesystemObjectsHKLM\Software\Classes\DirectoryHKLM\Software\Classes\FolderHKLM\Software\Classes\ProtocolsHKLM\Software\PoliciesHKLM\Software\Microsoft\Internet Explorer HKLM\System\CurrentControlSet\ServicesHKLM\System\CurrentControlSet\Control\Session Manager\KnownDLLsHKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg HKLM\Software\Microsoft\Windows\CurrentVersion\URLHKLM\Software\Microsoft\Windows\CurrentVersion\PoliciesHKLM\Software\Microsoft\Windows NT\CurrentVersion\WindowsHKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon HKLM\Software\Microsoft\Active Setup\Installed Components |

## nxlog whitelist

https://nxlog.co/question/4623/windows-event-id-whitelist-filter-question



```
`define MonitoredEventIds    ``4774``, ``4775``, ``4776``, ``4777``, ``4741``, ``4742``, ``4743``, ``4744``, ``4745``, ``4746``, \``                            ``4747``, ``4748``, ``4749``, ``4750``, ``4751``, ``4752``, ``4753``, ``4759``, ``4760``, ``4761``, \``                            ``4762``, ``4763``, ``4782``, ``4793``, ``4727``, ``4728``, ``4729``, ``4730``, ``4731``, ``4732``, \``                            ``4733``, ``4734``, ``4735``, ``4737``, ``4754``, ``4755``, ``4756``, ``4757``, ``4758``, ``4764``, \``                            ``4720``, ``4722``, ``4723``, ``4724``, ``4725``, ``4726``, ``4738``, ``4740``, ``4765``, ``4766``, \``                            ``4767``, ``4780``, ``4781``, ``4794``, ``5376``, ``5377``, ``4688``, ``4696``, ``4662``, ``5136``, \``                            ``5137``, ``5138``, ``5139``, ``4625``, ``4634``, ``4647``, ``4624``, ``4625``, ``4648``, ``4675``, \``                            ``4649``, ``4778``, ``4779``, ``4800``, ``4801``, ``4802``, ``4803``, ``5378``, ``5632``, ``5633``, \``                            ``4964``, ``4698``, ``4699``, ``4700``, ``4701``, ``4702``, ``5890``, ``5888``, ``5889``, ``4656``, \``                            ``4715``, ``4719``, ``4902``, ``4904``, ``4905``, ``4906``, ``4907``, ``4908``, ``4912``, ``4706``, \``                            ``4707``, ``4713``, ``4716``, ``4717``, ``4718``, ``4739``, ``4864``, ``4865``, ``4866``, ``4867``, \``                            ``4704``, ``4705``, ``4706``, ``4707``, ``4714``, ``4672``, ``4673``, ``4674``, ``4960``, ``4961``, \``                            ``4962``, ``4963``, ``4965``, ``5478``, ``5479``, ``5480``, ``5483``, ``5484``, ``5485``, ``5024``, \``                            ``5025``, ``5027``, ``5028``, ``5029``, ``5030``, ``5032``, ``5033``, ``5034``, ``5035``, ``5037``, \``                            ``5058``, ``5059``, ``4608``, ``4609``, ``4616``, ``4621``, ``4610``, ``4611``, ``4614``, ``4622``, \``                            ``4697``, ``4612``, ``4615``, ``4618``, ``4816``, ``5038``, ``5056``, ``5057``, ``5060``, ``5061``, \``                            ``5062` `<Input eventlog>``    ``Module  im_msvistalog``    ``<QueryXML>``        ``<QueryList>``            ``<Query Id=``'0'``>``                ``<Select Path=``'Security'``>*</Select>``            ``</Query>``        ``</QueryList>``    ``</QueryXML>``    ``<Exec>``        ``if` `$EventID NOT IN (%MonitoredEventIds%) drop();``    ``</Exec>``</Input>`
```



nxlog Windows Event Query

```
`#Local Users``#           A user's local group membership was enumerated``            ``<Select Path=``"Security"``>*[System[(EventID=``4798``)]]</Select>\``#           A security-enabled local group membership was enumerated``            ``<Select Path=``"Security"``>*[System[(EventID=``4799``)]]</Select>\``#Local & AD Users``#           The ACL was set on accounts which are members of administrators groups``            ``<Select Path=``"Security"``>*[System[(EventID=``4780``)]]</Select>\``#           Member added to the security-enabled universal group``            ``<Select Path=``"Security"``>*[System[(EventID=``4756``)]]</Select>\``#           Account Lockout``            ``<Select Path=``"Security"``>*[System[(EventID=``4625``)]]</Select>\``#           Account Logon``            ``<Select Path=``"Security"``>*[System[(EventID=``4624``)]]</Select>\``#           Account Logoff``            ``<Select Path=``"Security"``>*[System[(EventID=``4634``)]]</Select>\``#           A logon was attempted using explicit credentials.``            ``<Select Path=``"Security"``>*[System[(EventID=``4648``)]]</Select>\``#           An account was successfully logged on.``            ``<Select Path=``"Security"``>*[System[(EventID=``4624``)]]</Select>\``#Kerberos           ``#           An account was successfully logged on.``            ``<Select Path=``"Security"``>*[System[(EventID=``4624``)]]</Select>\``#           An account was successfully logged on.``            ``<Select Path=``"Security"``>*[System[(EventID=``4624``)]]</Select>\``#           Someone tried to reuse Kerberos ticket``            ``<Select Path=``"Security"``>*[System[(EventID=``4732``)]]</Select>\``#PowerShell``#           Transcription``            ``<Select Path=``"Windows Powershell"``>*[System[(EventID=``800``)]]</Select>\``#           Script Block & Module Logging``            ``<Select Path=``"Microsoft-Windows-PowerShell/Operational"``>*[System[(EventID=``4103``)]]</Select>\``#Process Auditing``#           A process has started``            ``<Select Path=``"Security"``>*[System[(EventID=``4688``)]]</Select>\``#           A process has exited``            ``<Select Path=``"Security"``>*[System[(EventID=``4689``)]]</Select>\``#DC Shadow``#           A computer account was changed``            ``<Select Path=``"Security"``>*[System[(EventID=``4742``)]]</Select>\``#           A directory service object was created``            ``<Select Path=``"Security"``>*[System[(EventID=``5137``)]]</Select>\``#           A directory service object was deleted``            ``<Select Path=``"Security"``>*[System[(EventID=``5141``)]]</Select>\``#           An Active Directory replica source naming context was removed``            ``<Select Path=``"Security"``>*[System[(EventID=``4929``)]]</Select>\``#Object (File & Registry) Auditing``#           Audit Policy Changed``            ``<Select Path=``"Security"``>*[System[(EventID=``4719``)]]</Select>\``#           Auditing Settings on Object Changed``            ``<Select Path=``"Security"``>*[System[(EventID=``4907``)]]</Select>\``#           An Object Was Deleted``            ``<Select Path=``"Security"``>*[System[(EventID=``4660``)]]</Select>\``#           An attempt was made to access an object``            ``<Select Path=``"Security"``>*[System[(EventID=``4663``)]]</Select>\``#           Registry key Modified``            ``<Select Path=``"Security"``>*[System[(EventID=``4657``)]]</Select>\``#Services & Setup``#           System time changed.``            ``<Select Path=``"Security"``>*[System[(EventID=``4616``)]]</Select>\``#           Registry key Modified``            ``<Select Path=``"Security"``>*[System[(EventID=``4657``)]]</Select>\``#           Setup``            ``<Select Path=``"Setup"``>*</Select>\``#Windows Firewall``#           Windows Firewall Stopped``            ``<Select Path=``"Security"``>*[System[(EventID=``5025``)]]</Select>\``            ``<Select Path=``"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"``>*</Select>\``#Sysmon          ``            ``<Select Path=``"Microsoft-Windows-Sysmon/Operational"``>*</Select>\``#Task Scheduler``            ``<Select Path=``"Microsoft-Windows-TaskScheduler/Operational"``>*</Select>\``#Windows Defender  ``            ``<Select Path=``"Microsoft-Windows-Windows Defender/Operational"``>*</Select>\``        ``</Query>\``    ``</QueryList>``</Input>` `<Output out>`
```

##   NX Log Hardening  

https://nxlog.co/documentation/nxlog-user-guide/hardening.html

Windows Hardeninng Checklist

- Dedicated Service Account
  - Login as a service
  - Grant access to nxlog folder
    - Modify
    - Read & Exec
    - List folder
    - Read
    - Write
  - Grant access to "Event Log reader " group.

## NXLog Troubleshooting

Error *failed to subscribe to msvistalog events, the channel was not found* [error code: 15007]

One of the log sources are missing from the end viewer

WIn2016 does been known to omit **Microsoft-Windows-Windows Defender/Operational**

### Generate Events

#### Event Create

https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate

```
`eventcreate /t error /id ``100` `/l application /d ``"Custom event in application log"`
```

#### Logger



```
`logger -l ``100.72``.``1.1` `"Hello world via TEST001"``-UDP`
```

#### WinDump

https://www.winpcap.org/windump/

```
`.\WinDump.exe -A -s ``800` `port ``514`
```



### SANS Event Logging

https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1511904841.pdf

### Powershell Logging Cheat Sheet

[Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf](https://ep2payments.atlassian.net/wiki/download/attachments/787087380/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf?version=1&modificationDate=1564312832675&cacheVersion=1&api=v2)

```
`WevtUtil qe ``"Windows PowerShell"`  `/q:``"*[System[(EventID=800)]]"` `| Selcet-string "get-childitem`
```

### DC Shadow

https://alsid.com/company/news/dcshadow-explained-technical-deep-dive-latest-ad-attack-technique

https://adsecurity.org/?p=1729

### Command Line Process Auditing

https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing

### Sysmon

https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

Config

https://github.com/SwiftOnSecurity/sysmon-config

### LSA

https://pentestlab.blog/tag/lsa/

### MS Audit Events

https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/appendix-a-security-monitoring-recommendations-for-many-audit-events

### File Auditing

Typical Web Server Friendly FIM



![file-audit](\img\file-audit.png)

### Registry Auditing

![reg-audit](\img\reg-audit.png)

https://www.itprotoday.com/windows-78/security-permissions-registry

### Skeleton Key

https://gallery.technet.microsoft.com/Aorato-Skeleton-Key-24e46b73



### Registry Audit

https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4657

https://www.sans.org/reading-room/whitepapers/critical/uncovering-indicators-compromise-ioc-powershell-event-logs-traditional-monitoring-tool-36352



### WUZAH OSSEC.conf

https://github.com/wazuh/wazuh/blob/master/src/win32/ossec.conf



### AppLocker via Powershell

https://www.rootusers.com/implement-applocker-rules-using-windows-powershell/



### Applocker Bypass List

https://github.com/api0cradle/UltimateAppLockerByPassList


