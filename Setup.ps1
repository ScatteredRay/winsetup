$ErrorActionPreference = "Stop"
Import-Module -Force (Join-Path $PSScriptRoot 'Util.psm1')

Do-Elevate ($myInvocation.MyCommand.Definition + " -noprofile")

Install-Feature "SetPath" {
    Append-Path-Env (Join-Path $HOME 'bin')
    Set-GlobalEnv 'HOME' $HOME
}

Install-Feature "CapsAsCtrl" {
    $hex = "00,00,00,00,00,00,00,00,02,00,00,00,1d,00,3a,00,00,00,00,00".Split(',') | % { "0x$_"};
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Keyboard Layout' -Name "Scancode Map" -PropertyType Binary -Value ([byte[]]$hex);
}

$RestartNeeded = $False

Install-Feature "HyperV" {
    if((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).State -ne 'Enabled') {
        $Ret = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
        $Script:RestartNeeded = ($Ret.RestartNeeded -eq $True)
    }
    else {
        # Don't restart if already enabled.
        Write-Host "HyperV already enabled."
    }
}

Install-Feature "ProjFS" {
    if((Get-WindowsOptionalFeature -Online -FeatureName Client-ProjFS).State -ne 'Enabled') {
        $Ret = Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -All -NoRestart
        $Script:RestartNeeded = ($Ret.RestartNeeded -eq $True)
    }
    else {
        # Don't restart if already enabled.
        Write-Host "ProjFS already enabled."
    }
}

Install-Feature "WindowsSandbox" {
    if((Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).State -ne 'Enabled') {
        $Ret = Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
        $Script:RestartNeeded = ($Ret.RestartNeeded -eq $True)
    }
    else {
        # Don't restart if already enabled.
        Write-Host "WindowsSandbox already enabled."
    }
}


Install-Feature "WSL" {
    if((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -ne 'Enabled') {
        $Ret = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
        $Script:RestartNeeded = ($Ret.RestartNeeded -eq $True)
    }
    else {
        # Don't restart if already enabled.
        Write-Host "WSL already enabled."
    }
    #$Script:RestartNeeded = $True # Testing!
}

Install-Feature "DisableUserChoiceProtectionDriver" {
    # This seems to prevent a bunch of later changes, we might need to reboot after.
    Disable-ScheduledTask "UCPD velocity" "\Microsoft\Windows\AppxDeploymentClient\"
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD" -Name "Start" -Value 4 -Type DWord
    $Script:RestartNeeded = $True
}

if($RestartNeeded) {
    #Register-ScheduledJob -FilePath $PSCommandPath -Name "ND-Setup-Script-Boot"
    #New-JobTrigger -User $Env:UserName -AtLogOn
    Write-Host "Restarting computer."
    Restart-Computer
    exit
}

Try {
    #Get-ScheduledJob -Name "ND-Setup-Script-Boot" -ErrorAction Stop | Unregister-ScheduledJob -Force -ErrorAction Stop
}
Catch {}

Install-Feature "WSLUpdate" {
    wsl.exe --update
}

Install-Feature "PSHelp" {
    Update-Help
}

Install-Feature "PowerToys" {
    #TODO: silent not working!
    Download-Run "PowerToys" $installerUrls.PowerToys "PowerToysSetup.exe" "/silent"
}

# A bunch of features from Chris Titus's winutil
# https://github.com/ChrisTitusTech/winutil
# Prefer to maintain them here,
# He has a bunch of json we could use to maintain this automatically

Install-Feature "DisableSearchSuggestions" {
    Set-TypedItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableSearchBoxSuggestions' -Type DWord -Value 1 -Force
    Stop-Process -name explorer -force
}

Install-Feature "DisableBingSearch" {
    Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name BingSearchEnabled -Type DWord -Value 0
}

Install-Feature "DarkMode" {
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -Type DWord -Value 0
}

Install-Feature "DetailedBSoD" {
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name DisplayParameters -Type DWord -Value 1
}

Install-Feature "ShowHiddenFiles" {
    Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Type DWord -Value 1
}

Install-Feature "ShowExtensions" {
    Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt -Type DWord -Value 0
}

Install-Feature "DisableMouseAcceleration" {
    # 1, 6, 10 seems to be default
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Mouse" -Name MouseSpeed -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Mouse" -Name MouseThreshold1 -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Mouse" -Name MouseThreshold2 -Type DWord -Value 0
}

Install-Feature "DisableStickyKeys" {
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -Type DWord -Value 506
}

Install-Feature "DisableFilterKeys" {
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name Flags -Type DWord -Value 122
}

Install-Feature "DisableToggleKeys" {
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name Flags -Type DWord -Value 58
}

Install-Feature "DisableTaskbarSearch" {
    Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search\" -Name SearchboxTaskbarMode -Type DWord -Value 0
}

Install-Feature "DisableTaskbarWidgets" {
    Set-TypedItemProperty -Path "HKLM:\Software\Policies\Microsoft\Dsh" -Name AllowNewsAndInterests -Type DWord -Value 0
    #Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name TaskbarDa -Type DWord -Value 0
}

Install-Feature "DisableActivityHistory" {
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name EnableActivityFeed -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name PublishUserActivities -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name UploadUserActivities -Type DWord -Value 0
}

Install-Feature "DisableConsumerFeatures" {
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Type DWord -Value 1
}

Install-Feature "DisableGameDVR" {
    # Think this is for the record 30sec button

    Set-TypedItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_Enabled -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_HonorUserFSEBehaviorMode -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKCU:\System\GameConfigStore" -Name GameDVR_EFSEFeatureFlags -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\System\GameConfigStore" -Name AllowGameDVR -Type DWord -Value 0
}


Install-Feature "EdgeDebloat" {
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "CreateDesktopShortcutDefault" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PersonalizationReportingEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowRecommendationsEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "UserFeedbackAllowed" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ConfigureDoNotTrack" -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AlternateErrorPagesEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeCollectionsEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeShoppingAssistantEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "MicrosoftEdgeInsiderPromotionEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PersonalizationReportingEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowMicrosoftRewards" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DiagnosticData" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeAssetDeliveryServiceEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeCollectionsEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "CryptoWalletEnabled" -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WalletDonationEnabled" -Type DWord -Value 0
}

Install-Feature "DisableLocationTracking" {
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Deny"
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 0
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type "DWord" -Value 0
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type "DWord" -Value 0
}

Install-Feature "ManualStartServices" {
    Add-Type -Assemblyname System.ServiceProcess
    $AutomaticDelayedStart =  [System.ServiceProcess.ServiceStartMode]::Automatic # AutomaticDelayedStart in pwsh 6 and above.

    Get-Service -Name AJRouter -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name ALG -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name AppMgmt -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name AppReadiness -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name AppVClient -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    #Get-Service -Name AppXSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name Appinfo -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name AssignedAccessManagerSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name AudioEndpointBuilder -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name AudioSrv -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name Audiosrv -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name AxInstSV -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name BDESVC -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name BFE -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name BITS -ErrorAction SilentlyContinue | Set-Service -StartupType $AutomaticDelayedStart -ErrorAction Stop
    Get-Service -Name BTAGService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name BcastDVRUserService_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    #Get-Service -Name BluetoothUserService_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop  # Parameter is incorrect
    #Get-Service -Name BrokerInfrastructure -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name Browser -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name BthAvctpSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name BthHFSrv -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name CDPSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name CDPUserSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name COMSysApp -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name CaptureService_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name CertPropSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name ClipSVC -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop  # Protected
    #Get-Service -Name ConsentUxUserSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    #Get-Service -Name CoreMessagingRegistrar -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    #Get-Service -Name CredentialEnrollmentManagerUserSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name CryptSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name CscService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name DPS -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    #Get-Service -Name DcomLaunch -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name DcpSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name DevQueryBroker -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name DeviceAssociationBrokerSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name DeviceAssociationService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name DeviceInstall -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name DevicePickerUserSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    #Get-Service -Name DevicesFlowUserSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name Dhcp -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name DiagTrack -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name DialogBlockingService -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name DispBrokerDesktopSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name DisplayEnhancementService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name DmEnrollmentSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name Dnscache -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    #Get-Service -Name DoSvc -ErrorAction SilentlyContinue | Set-Service -StartupType $AutomaticDelayedStart -ErrorAction Stop # Protected
    Get-Service -Name DsSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name DsmSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name DusmSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name EFS -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name EapHost -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name EntAppSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name EventLog -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name EventSystem -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name FDResPub -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name Fax -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name FontCache -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name FrameServer -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name FrameServerMonitor -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name GraphicsPerfSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name HomeGroupListener -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name HomeGroupProvider -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name HvHost -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name IEEtwCollectorService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name IKEEXT -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name InstallService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name InventorySvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name IpxlatCfgSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name KeyIso -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name KtmRm -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name LSM -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name LanmanServer -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name LanmanWorkstation -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name LicenseManager -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name LxpSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name MSDTC -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name MSiSCSI -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name MapsBroker -ErrorAction SilentlyContinue | Set-Service -StartupType $AutomaticDelayedStart -ErrorAction Stop
    Get-Service -Name MapsBroker -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop #AutomaticDelayedStart
    Get-Service -Name McpManagementService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name MessagingService_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name MicrosoftEdgeElevationService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name MixedRealityOpenXRSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name MpsSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name MsKeyboardFilter -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name NPSMSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name NaturalAuthentication -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name NcaSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name NcbService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name NcdAutoSetup -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name NetSetupSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name NetTcpPortSharing -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name Netlogon -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name Netman -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name NgcCtnrSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    #Get-Service -Name NgcSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name NlaSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name OneSyncSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Parameter is incorrect
    #Get-Service -Name P9RdrService_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name PNRPAutoReg -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name PNRPsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name PcaSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name PeerDistSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name PenService_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name PerfHost -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name PhoneSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name PimIndexMaintenanceSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name PlugPlay -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name PolicyAgent -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name Power -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name PrintNotify -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name PrintWorkflowUserSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name ProfSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name PushToInstall -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name QWAVE -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name RasAuto -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name RasMan -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name RemoteAccess -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name RetailDemo -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name RmSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name RpcEptMapper -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name RpcLocator -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name RpcSs -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name SCPolicySvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SCardSvr -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SDRSVC -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SEMgrSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SENS -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name SNMPTRAP -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SNMPTrap -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SSDPSRV -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SamSs -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name ScDeviceEnum -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name Schedule -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Proteced
    #Get-Service -Name SecurityHealthService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    #Get-Service -Name Sense -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name SensorDataService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SensorService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SensrSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SessionEnv -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name SgrmBroker -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name SharedAccess -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SharedRealitySvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name ShellHWDetection -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name SmsRouter -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name Spooler -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name SstpSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name StateRepository -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name StiSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name StorSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name SysMain -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    #Get-Service -Name SystemEventsBroker -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name TabletInputService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name TapiSrv -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name TermService -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    #Get-Service -Name TextInputManagementService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name Themes -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name TieringEngineService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name TimeBroker -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name TimeBrokerSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name TokenBroker -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name TrkWks -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name TroubleshootingSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name TrustedInstaller -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name UI0Detect -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name UdkUserSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name UevAgentService -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name UmRdpService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name UnistoreSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    #Get-Service -Name UserDataSvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name UserManager -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name UsoSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name VGAuthService -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name VMTools -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name VSS -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name VacSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name VaultSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name W32Time -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WEPHOSTSVC -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WFDSConMgrSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WMPNetworkSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WManSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WPDBusEnum -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WSService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WSearch -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop #AutomaticDelayedStart
    #Get-Service -Name WaaSMedicSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name WalletService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WarpJITSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WbioSrvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name Wcmsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name WcsPlugInService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name WdNisSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name WdiServiceHost -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WdiSystemHost -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WebClient -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name Wecsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WerSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WiaRpc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name WinDefend -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    #Get-Service -Name WinHttpAutoProxySvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name WinRM -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name Winmgmt -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name WlanSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name WpcMonSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name WpnService -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name WpnUserService_* -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name XblAuthManager -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name XblGameSave -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name XboxGipSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name XboxNetApiSvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name autotimesvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name bthserv -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name camsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name cbdhsvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name cloudidsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name dcsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name defragsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name diagnosticshub.standardcollector.service -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name diagsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name dmwappushservice -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name dot3svc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name edgeupdate -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name edgeupdatem -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name embeddedmode -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name fdPHost -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name fhsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name gpsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Protected
    Get-Service -Name hidserv -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name icssvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name iphlpsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name lfsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name lltdsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name lmhosts -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name msiserver -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop # Protected
    Get-Service -Name netprofm -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name nsi -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name p2pimsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name p2psvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name perceptionsimulation -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name pla -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name seclogon -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name shpamsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name smphost -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name spectrum -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name sppsvc -ErrorAction SilentlyContinue | Set-Service -StartupType $AutomaticDelayedStart -ErrorAction Stop # Protected
    Get-Service -Name ssh-agent -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name svsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name swprv -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name tiledatamodelsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop
    Get-Service -Name tzautoupdate -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name uhssvc -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction Stop
    Get-Service -Name upnphost -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vds -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vm3dservice -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmicguestinterface -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmicheartbeat -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmickvpexchange -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmicrdv -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmicshutdown -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmictimesync -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmicvmsession -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmicvss -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name vmvss -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name wbengine -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name wcncsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name webthreatdefsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name webthreatdefusersvc_* -ErrorAction SilentlyContinue | Set-Service -StartupType Automatic -ErrorAction Stop # Parameter is incorrect
    Get-Service -Name wercplsupport -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name wisvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name wlidsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name wlpasvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name wmiApSrv -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name workfolderssvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    #Get-Service -Name wscsvc -ErrorAction SilentlyContinue | Set-Service -StartupType $AutomaticDelayedStart -ErrorAction Stop # Protected
    Get-Service -Name wuauserv -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
    Get-Service -Name wudfsvc -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction Stop
}

Install-Feature "DisableStorageSense" {
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 0 -Type Dword -Force
}

Install-Feature "Remove3DObjects" {
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

Install-Feature "RemoveCopilot" {
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Type Dword -Force
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1 -Type Dword -Force
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Type Dword -Force
    Remove-AppxPackage -AllUsers -Package (Get-AppxPackage -AllUsers -Name Microsoft.Copilot)
}

Install-Feature "RemoveMSTeams" {
    Get-AppxPackage -AllUsers *MSTeams* | Remove-AppxPackage -AllUsers
}

Install-Feature "RemoveOneDrive" {
    Get-Process "OneDrive" -ErrorAction SilentlyContinue | Stop-Process
    Start-Process -FilePath "$env:SystemRoot\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -WindowStyle Hidden -Wait
    Remove-Item -Path "$env:UserProfile\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LocalAppData\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
}

Install-Feature "DisableWindowsTelemetry" {
    # Missing a script here: https://github.com/ChrisTitusTech/winutil/blob/main/docs/dev/tweaks/Essential-Tweaks/Tele.md

    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop

    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -ErrorAction Stop
    #Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\MareBackup" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\StartupAppTask" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\PcaPatchDbTask" -ErrorAction Stop
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Maps\MapsUpdateTask" -ErrorAction Stop


    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name ContentDeliveryAllowed -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name OemPreInstalledAppsEnabled -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name PreInstalledAppsEnabled -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name PreInstalledAppsEverEnabled -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SilentInstalledAppsEnabled -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SubscribedContent -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name SystemPaneSuggestionsEnabled -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name NumberOfSIUFInPeriod -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name DoNotShowFeedbackNotifications -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableTailoredExperiencesWithDiagnosticData -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name DisabledByGroupPolicy -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name DODownloadMode -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name fAllowToGetHelp -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name EnthusiastMode -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name ShowTaskViewButton -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name PeopleBand -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name LaunchTo -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name SearchOrderConfig -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name SystemResponsiveness -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name NetworkThrottlingIndex -Type DWord -Value 4294967295
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Desktop" -Name MenuShowDelay -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Desktop" -Name AutoEndTasks -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name ClearPageFileAtShutdown -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name Start -Type DWord -Value 2
    Set-TypedItemProperty -Path "HKCU:\Control Panel\Mouse" -Name MouseHoverTime -Type String -Value 400
    Set-TypedItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name IRPStackSize -Type DWord -Value 30
    Set-TypedItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name EnableFeeds -Type DWord -Value 0
    Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name HideSCAMeetNow -Type DWord -Value 1
    Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name ScoobeSystemSettingEnabled -Type DWord -Value 0

    Set-TypedItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name ShellFeedsTaskbarViewMode -Type DWord -Value 2 # UCPD
}

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');