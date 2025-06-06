$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -parent $PSCommandPath

$config = $ExecutionContext.InvokeCommand.ExpandString((Get-Content (Join-Path $scriptDir "default.json"))) | ConvertFrom-Json

if([System.IO.File]::Exists((Join-Path $scriptDir "workstation.json")))
{
    $wcfg = Get-Content (Join-Path $scriptDir "workstation.json") | ConvertFrom-Json
    $wcfg.PSObject.Properties | ForEach-Object { $config.($_.Name) = $_.Value }
}

Add-Type -AssemblyName System.Windows.Forms
$Form = New-Object system.Windows.Forms.Form
$Form.AutoSize = $TRUE

$Panel = New-Object System.Windows.Forms.FlowLayoutPanel
$Panel.FlowDirection = "TopDown"
$Panel.WrapContents = $false
$Panel.Dock = "Fill"
#$Panel.AutoSize = $TRUE
$Panel.AutoScroll = $TRUE
$Form.Controls.Add($Panel)
$Form.Width = 400
$Form.Height = 800

ForEach ($Prop in $config.PSObject.Properties) {
    if($Prop.TypeNameOfValue -eq "System.Boolean")
    {
        $PropName = $Prop.Name
        $ChkBox = New-Object System.Windows.Forms.CheckBox
        $ChkBox.Text = $PropName
        $ChkBox.Checked = $Prop.Value
        $ChkBox.Add_CheckedChanged({$config.$PropName = $ChkBox.Checked}.GetNewClosure())
        $ChkBox.AutoSize = $True
        $Panel.Controls.Add($ChkBox)
    }
    elseif($Prop.TypeNameOfValue -eq "System.String")
    {
        $PropName = $Prop.Name
        $TxtPanel = New-Object System.Windows.Forms.FlowLayoutPanel
        $TxtPanel.FlowDirection = "LeftToRight"
        $TxtPanel.WrapContents = $false
        $TxtPanel.Dock = "Fill"
        $TxtPanel.AutoSize = $TRUE
        $Panel.Controls.Add($TxtPanel)

        $Lbl = New-Object System.Windows.Forms.Label
        $Lbl.Text = $Prop.Name
        $Lbl.AutoSize = $True
        $TxtPanel.Controls.Add($Lbl)
        $TxtBox = New-Object System.Windows.Forms.TextBox
        $TxtBox.Text = $Prop.Value
        $TxtBox.Add_TextChanged({$config.$PropName = $TxtBox.Text}.GetNewClosure())
        $TxtBox.AutoSize = $TRUE
        $TxtPanel.Controls.Add($TxtBox)
    }
    else
    {
        $Lbl = New-Object System.Windows.Forms.Label
        $Lbl.Text = $Prop.Name
        $Lbl.AutoSize = $True
        $Panel.Controls.Add($Lbl)

    }
}

$BtnOk = New-Object System.Windows.Forms.Button
$BtnOk.Text = "OK"
$BtnOk.Add_Click({$Form.Close()})
$Panel.Controls.Add($BtnOk)

$Form.ShowDialog()

ConvertTo-Json $config | Set-Content (Join-Path $scriptDir "workstation.json")