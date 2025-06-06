$scratchDir = "C:\Temp\Scratch\"

Function Get-SessionArgs {
    Param($Session)
    if($Session -ne $Null) {
        return @{ Session = $Session }
    }
    else {
        return @{}
    }
}

Function Read-CommandArguments {
    Param($Arguments)
    $NamedArgs = @{}
    $PosArgs = @()
    for($i = 0; $i -lt $Arguments.Length; $i++) {
        $A = $Arguments[$i]
        if($A -is [string] -and $A[0] -eq '-') {
            $NamedArgs[$A.substring(1)] = $Arguments[$i+1]
            $i++
        }
        else {
            $PosArgs += $A
        }
    }
    $NamedArgs, $PosArgs
}

Function Invoke-RemoteCommand {
    Param([Parameter(Position=0)]
          $Session,
          [Parameter(Position=1, ValueFromRemainingArguments)]
          $Args)
    $SessionArgs = Get-SessionArgs $Session
    $cmd, $rest = $Args
    if($rest -isnot [array]) {
        $rest = @($rest)
    }
    $nargs, $pargs = Read-CommandArguments $rest
    $ArgumentList = @(
        $cmd,
        $nargs,
        $pargs
    )
    Invoke-Command -ScriptBlock {
        Param($cmd, $nargs, $pargs)
        & $cmd @nargs @pargs
    } -ArgumentList $ArgumentList @SessionArgs
}

Function Confirm-Dir {
    Param([string] $dir, $Session)
    if(!(Invoke-RemoteCommand -Session $Session test-path $dir))
    {
        [void](Invoke-RemoteCommand -Session $Session New-Item -path $dir -type directory)
    }
    $dir
}

Function Get-ScratchPath {
    Param($Session)
    $scratchDir = Confirm-Dir -Session $Session -Dir "C:\Temp\Scratch\"
    return $scratchDir
}

Function Get-UniqueScratchPath {
    Param($Session)
    return Confirm-Dir -Session $Session (Join-Path (Get-ScratchPath -Session $Session) (New-Guid).Guid)
}

Function Ensure-Dir
{
    Param([string] $dir)
    if(!(test-path $dir))
    {
        [void](New-Item -path $dir -type directory -ErrorAction Stop)
    }
    $Dir
}

Function Ensure-Parent-Dir
{
    Param([string] $path)
    Ensure-Dir (Split-Path -parent $path)
}

if($PSCommandPath)
{
    $scriptDir = Split-Path -parent $PSCommandPath
}
else
{
    $scriptDir = Convert-Path .
}

$cfgDir = Join-Path $scriptDir "config"

$P4Path = "C:\Program Files\Perforce\p4.exe"
Set-Alias -Name p4 -Value $P4Path

Function Load-Config
{
    $config = Get-Content (Join-Path $scriptDir "workstation.json") | ConvertFrom-Json
    return $config
}

Function Save-Config
{
    Param(
        $Config
    )
    ConvertTo-Json $Config | Set-Content (Join-Path $scriptDir "workstation.json")
}

Function Set-ConfigValue
{
    Param(
        [string] $Param,
        $Value
    )
    $Config = Load-Config
    $Config.$Param = $Value
    Save-Config $Config
}

Function Set-Installed
{
    Param(
        [string] $Feature
    )
    Write-Host "Marking feature $Feature as Installed"
    Set-ConfigValue $Feature $False
}

Function Test-LastError {
    if($LASTEXITCODE -ne 0)
    {
        $Callstack = Get-PSCallStack | Out-String

        Throw @"
Command Failed.
$Callstack
"@
    }
}

Function Load-InstallerUrls
{
    Param([switch]$Versions)
    $urls = Get-Content (Join-Path $scriptDir "InstallerUrls.json") | ConvertFrom-Json
    if($Versions) {
        $u = @{}
        [void]($urls.psobject.properties | % { $u[$_.Name] = if($_.Value.url) { $_.Value } else { [PSCustomObject]@{ url = $_.Value } } })
        return [PSCustomObject]$u
    }
    else {
        $u = @{}
        [void]($urls.psobject.properties | % { $u[$_.Name] = if($_.Value.url) { $_.Value.url } else { $_.Value } })
        return [PSCustomObject]$u
    }
    return $urls
}

function Do-Elevate
{
    Param($cmdDef)
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
    if(!($myWindowsPrincipal.IsInRole($adminRole)))
    {
        Start-Process PowerShell -Verb runAs -ArgumentList $cmdDef -Wait
        Exit
    }
}

Function Install-Font {
    Param ($fontFile)
    (New-Object -ComObject Shell.Application).Namespace(0x14).CopyHere($fontFile.FullName)
}


Function Append-Path-Env
{
    Param([string] $newDir)
    $oldPath = (Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Environment' -Name 'PATH').Path
    $newPath = "$newDir;$oldPath"
    Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Environment' -Name 'PATH' -Value $newPath -ErrorAction Stop
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + $newPath #[System.Environment]::GetEnvironmentVariable("Path","User") 
}

Function Set-GlobalEnv
{
    Param([string] $varName, [string] $varValue)
    Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Environment' -Name $varName -Value $varValue
    [environment]::SetEnvironmentVariable($varName, $varValue)
    #TODO: Broadcast WM_SETTINGCHANGE to get change to take effect.
}

Function Invoke-DownloadRequest
{
    Param([Parameter(Position=0)][Uri] $Uri, [String] $OutFile)
    # Wrapping Invoke-WebRequest so we can provide some options to speed up the download

    # It appears that the progress bar slows down the downloads a lot
    $OldProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -ErrorAction Stop
    $ProgressPreference = $OldProgressPreference
}

Function Run-Installer
{
    Param([string] $name, [string] $file, $runParams, $Session)
    $SessionArgs = Get-SessionArgs $Session
    $proc = if($runParams)
    {
        Invoke-Command -ScriptBlock {
            Param($file, $runParams)
            Start-Process -FilePath $file -ArgumentList $runParams -PassThru -Wait -ErrorAction Stop
        } -ArgumentList @($file, $runParams) @SessionArgs
    }
    else
    {
        Invoke-Command -ScriptBlock {
            Param($file)
            Start-Process -FilePath $file -PassThru -Wait -ErrorAction Stop
        } -ArgumentList @($file) @SessionArgs
    }
    if($proc.ExitCode -ne 0)
    {
        Throw "Error installing"
    }
    return $proc.ExitCode
}

Function P4-Download-Tree
{
    Param([string] $p4Path, [string] $downloadPath)

    Ensure-Dir $downloadPath
    $p4Filter = (Join-Path $p4Path '...').replace('\', '/')

    p4 files -e $p4Filter | Select-String -Pattern '^(//[^#]*)#([0-9]*) - ' | ForEach-Object {
        $p4File = $_.Matches[0].Groups[1].Value
        $p4Rev = $_.Matches[0].Groups[2].Value
        $p4FullPath = "$p4File#$p4Rev"
        $relPath = $p4File.Replace($p4Path, '')
        $localPath = Join-Path $downloadPath $relPath
        p4 print -o $localPath $p4FullPath
        Test-LastError
    }
    Test-LastError
}

Function P4-Download-Tree-Run
{
    Param([string] $name, [string] $urlPath, [string] $runFile, [string] $downloadPrefix, [string] $runParams)

    $downloadPath = Join-Path (Get-ScratchPath) $downloadPrefix
    $runPath = Join-Path $downloadPath $runFile
    P4-Download-Tree $urlPath $downloadPath
    $proc = if($runParams)
    {
        Start-Process -FilePath $runPath -ArgumentList $runParams -PassThru -Wait -ErrorAction Stop
    }
    else
    {
        Start-Process -FilePath $runPath -PassThru -Wait -ErrorAction Stop
    }
    if($proc.ExitCode -ne 0)
    {
        Throw "Error installing"
    }
    return $proc.ExitCode
}

Function P4-Download-Run
{
    Param([string] $name, [string] $urlPath, [string] $downloadFile, [string] $runParams)
    $downloadPath = Join-Path (Get-ScratchPath) $downloadFile
    p4 print -o $downloadPath $urlPath
    Test-LastError
    $proc = if($runParams)
    {
        Start-Process -FilePath $downloadPath -ArgumentList $runParams -PassThru -Wait -ErrorAction Stop
    }
    else
    {
        Start-Process -FilePath $downloadPath -PassThru -Wait -ErrorAction Stop
    }
    if($proc.ExitCode -ne 0)
    {
        Throw "Error installing"
    }
    return $proc.ExitCode
}

Function Download-Run
{
    Param([string] $name, [string] $urlPath, [string] $downloadFile, [string] $runParams, $Session)
    $downloadPath = Join-Path (Get-ScratchPath) $downloadFile
    Invoke-RemoteCommand -Session $Session Invoke-DownloadRequest $urlPath -OutFile $downloadPath  -ErrorAction Stop
    return Run-Installer -Session $Session $name $downloadPath $runParams
}

Function Download-RunMSI
{
    Param([string] $name, [string] $urlPath, [string] $downloadFile, [string] $runParams)
    if([string]::IsNullOrEmpty($downloadFile)) {
        $downloadFile = ([uri]$urlPath).Segments[-1]
    }
    $downloadPath = Join-Path (Get-ScratchPath) $downloadFile
    Invoke-DownloadRequest $urlPath -OutFile $downloadPath  -ErrorAction Stop
    return Run-Installer $name 'msiexec' ("/i", $downloadPath, "/qn")
}

Function Download-AddAppXPackage
{
    Param([string] $name, [string] $urlPath, [string] $runParams)
    $downloadFile = ([uri]$urlPath).Segments[-1]
    $downloadPath = Join-Path (Get-ScratchPath) $downloadFile
    Invoke-DownloadRequest $urlPath -OutFile $downloadPath  -ErrorAction Stop
    return Add-AppxPackage -Path $downloadPath
}

Function Expand-MSI
{
    Param([string] $Path, [string] $DestinationPath)
    $lessmsipath = ls (Join-Path $PSScriptRoot "..\bin\packages\lessmsi-*" )
    $lessmsi = Get-ChildItem (Join-Path $lessmsipath "lessmsi.exe")

    [void](& $lessmsi x $Path "$DestinationPath\")
}

Function Download-ExtractMSI
{
    Param([string] $urlPath, [string] $extractionPath, [string]$extractionPrefix)
    $Filename = ([uri]$urlPath).Segments[-1]
    $scratch = Ensure-Dir (Get-UniqueScratchPath)
    $TempDest = Join-Path $scratch $Filename
    Invoke-DownloadRequest $urlPath -OutFile $TempDest -ErrorAction Stop
    $ExtractDir = Join-Path $scratch ([io.path]::GetFileNameWithoutExtension($Filename))
    Expand-MSI $TempDest $ExtractDir
    Copy-Item (Join-Path $ExtractDir "$extractionPrefix\*") $extractionPath -Recurse
}

Function Expand-Archive7z
{
    Param([string] $Path, [string] $DestinationPath)
    $DestinationPath = (Get-Item $DestinationPath).FullName
    $7z = $Null
    if(Get-Command 7z -ErrorAction SilentlyContinue) {
        $7z = "7z"
    }
    elseif(Get-Command 7za -ErrorAction SilentlyContinue) {
        $7z = "7za"
    }
    else {
        $7z = ls (Join-Path $PSScriptRoot "..\bin\packages\7z*\7z.exe") -ErrorAction SilentlyContinue | Sort -Descending | Select -First 1
    }

    if(![string]::IsNullOrEmpty($7z)) {
        [void] (& $7z x $Path "-o$DestinationPath" -y)
    }
    else {
        Expand-Archive -Path $Path -DestinationPath $DestinationPAth
    }
}

Function Download-To
{
    Param([string] $urlPath, [string] $destinationPath)
    $Filename = ([uri]$urlPath).Segments[-1]
    Invoke-DownloadRequest $urlPath -OutFile (Join-Path $destinationPath $Filename) -ErrorAction Stop
}

Function Download-Extract
{
    Param([string] $urlPath, [string] $extractionPath)
    $Filename = ([uri]$urlPath).Segments[-1]
    $TempDest = Join-Path (Get-ScratchPath) $Filename
    Invoke-DownloadRequest $urlPath -OutFile $TempDest -ErrorAction Stop
    Expand-Archive7z $TempDest $extractionPath
}

Function Download-ExtractPack
{
    Param([string] $urlPath, [string] $extractionRoot)
    $PackageName = ([system.io.fileinfo]([uri]$urlPath).Segments[-1]).BaseName
    $extractionPath = Join-Path $extractionRoot $PackageName
    Download-Extract $urlPath $extractionPath
    return $extractionPath
}

Function Copy-Tree-Run
{
    Param([string] $name, [string] $urlPath, [string] $runFile, [string] $downloadPrefix, [string] $runParams)

    $downloadPath = Join-Path (Get-ScratchPath) $downloadPrefix
    $runPath = Join-Path $downloadPath $runFile
    cp -r $urlPath $downloadPath
    return Run-Installer $name $runPath $runParams
}

Function Install-Certificate {
    Param([string] $certPath)
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

    $cert.import($certPath, $Null, "Exportable,PersistKeySet")

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
    $store.open("ReadWrite")
    $store.add($cert)
    $store.close()
}

Function Install-Feature {
    Param(
        [string] $Feature,
        [scriptblock] $Installer
    )
    $config = Load-Config
    if($config.$Feature) {
        Try {
            Write-Host "Installing $Feature"
            & ($Installer)
            Set-Installed $Feature
        }
        Catch [System.Security.SecurityException] {
            Write-Warning "Error Installing Feature: $Feature due to a Security Exception"
        }
        Catch [System.Management.Automation.ItemNotFoundException] {
            Write-Warning $_.Exception.Message
            Write-Warning $_.Exception.StackTrace
            Write-Warning "Error Installing Feature: $Feature due to Record Not Found"
        }
        Catch {
            Write-Warning $_
            Write-Warning "Error Installing Feature: $Feature"
        }
    }
}

Function Download-InstallCertificate {
    Param([string] $urlPath, [string] $downloadFile)
    $downloadPath = Join-Path (Get-ScratchPath) $downloadFile
    Invoke-DownloadRequest $urlPath -OutFile $downloadPath
    return Install-Certificate $downloadPath
}

Function Set-TypedItemProperty {
    Param($Path, $Name, $Type, $Value)
    # So we can create if it doesn't exist
    if(!(Test-Path $Path)) {
        Write-Host "Creating $Path."
        New-Item -Path $Path -Force -ErrorAction Stop
    }
    Set-ItemProperty -Path $Path -Name $Name -Type $Type -Value $Value -Force -ErrorAction Stop
}

Function Get-AllInstalledApps {
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString, QuietUninstallString
    Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString, QuietUninstallString
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString, QuietUninstallString
}

Function Get-InstalledApp {
    Param(
        [ValidateNotNullOrEmpty()]
        [string] $AppName,
        [string] $Version
    )
    $InstalledApps = Get-AllInstalledApps
    $MatchingApps = $InstalledApps | Where -Property DisplayName -Like $AppName
    if(![string]::IsNullOrEmpty($Version)) {
        $MatchingApps = $MatchingApps | Where -Property DisplayVersion -Like $Version
    }
    return $MatchingApps
}

Function Confirm-AppRemoved {
    Param(
        [ValidateNotNullOrEmpty()]
        [string] $AppName,
        [string] $Version
    )
    $App = Get-InstalledApp -AppName $AppName -Version $Version
    if($App) {
        if ($App.QuietUninstallString[0] -eq '"') {
            iex "& $($App.QuietUninstallString)"
        }
        else {
            iex $App.QuietUninstallString
        }
    }
}

Export-ModuleMember -Function '*'
Export-ModuleMember -Variable 'scratchDir'
Export-ModuleMember -Variable 'scriptDir'
Export-ModuleMember -Variable 'cfgDir'