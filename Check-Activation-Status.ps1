function ExitScript($ExitCode = 0)
{
    if (!$psISE) {
        Write-Host
        Write-Host "Press any key to exit."
        [void]$Host.UI.RawUI.ReadKey(6)
    }
    Exit $ExitCode
}

function Cmdize
{
#    $W=$Host.UI.RawUI.WindowSize;$B=$Host.UI.RawUI.BufferSize;$W.Width=80;$W.Height=30;$B.Width=80;$B.Height=300;$Host.UI.RawUI.WindowSize=$W;$Host.UI.RawUI.BufferSize=$B;
    $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(80,30)
    $Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(80,300)
    $Host.UI.RawUI.BackgroundColor = 0
    $Host.UI.RawUI.ForegroundColor = 7
    $r = New-Object System.Management.Automation.Host.Rectangle @(-1,-1,-1,-1)
    $b = New-Object System.Management.Automation.Host.BufferCell @(' ','Gray','Black',0)
    $Host.UI.RawUI.SetBufferContents($r, $b)
    clear
}

if ($null -EQ $PSVersionTable)
{
    Write-Host "==== ERROR ====`n"
    Write-Host 'Windows PowerShell 1.0 is not supported by this script.'
    ExitScript 1
}

if ($ExecutionContext.SessionState.LanguageMode.value__ -NE 0) {
    Write-Host "==== ERROR ====`n"
    Write-Host 'Windows PowerShell is not running in Full Language Mode.'
    ExitScript 1
}

$winbuild = 1
try {
    $winbuild = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$env:SystemRoot\System32\kernel32.dll").FileBuildPart
} catch {
    $winbuild = [int]([WMI]'Win32_OperatingSystem=@').BuildNumber
}

if ($winbuild -LT 6000) {
    Write-Host "==== ERROR ====`n"
    Write-Host 'This build of Windows is not supported by this script.'
    ExitScript 1
}

if ($MyInvocation.InvocationName -EQ "&") {
    Cmdize
}

$line2 = "************************************************************"
$line3 = "____________________________________________________________"

function UnQuickEdit
{
    $t=[AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 1).DefineDynamicModule((Get-Random), $False).DefineType((Get-Random));
    $t.DefinePInvokeMethod('GetStdHandle', 'kernel32.dll', 22, 1, [IntPtr], @([Int32]), 1, 3).SetImplementationFlags(128);
    $t.DefinePInvokeMethod('SetConsoleMode', 'kernel32.dll', 22, 1, [Boolean], @([IntPtr], [Int32]), 1, 3).SetImplementationFlags(128);
    $k=$t.CreateType();
    $v=(0x0080, 0x00A0)[!($winbuild -GE 10586)];
    $b=$k::SetConsoleMode($k::GetStdHandle(-10), $v);
}

function GetID($strSLP, $strAppId, $strProperty = "ID")
{
#$_qr = "(([WMISEARCHER]'SELECT $strProperty FROM $strSLP WHERE ApplicationID=''$strAppId'' AND PartialProductKey IS NOT NULL').Get()).Properties"
#$_qr = "([WMISEARCHER]'SELECT $strProperty FROM $strSLP WHERE ApplicationID=''$strAppId'' AND PartialProductKey IS NOT NULL').Get() | select -Expand $strProperty -EA 0"
#iex $_qr
gwmi $strSLP $strProperty -Filter "ApplicationID='$strAppId' AND PartialProductKey IS NOT NULL" | select -Expand $strProperty
}

function DetectPKey($strSLP, $strAppId, $strProperty = "ID")
{
$bReturn = $false
gwmi $strSLP $strProperty -Filter "ApplicationID='$strAppId' AND PartialProductKey IS NOT NULL" | select $strProperty -EA 0 | foreach {$bReturn = $true}
#. GetID $strSLP $strAppId
#try {iex $_qr | select "ID" -EA 1} catch {$bReturn = $false}
#try {gwmi $strSLP $strProperty -Filter "ApplicationID='$strAppId'" -EA 1 | select -Expand Properties -EA 1 | Out-Null} catch {$bReturn = $false}
return $bReturn
}

function QueryService($strSLS, $strProperties)
{
#$_qr = "(([WMISEARCHER]'SELECT $strProperties FROM $strSLS').Get()).Properties | foreach {$_.Name+'='+$_.Value}"
#$_qr = "([WMISEARCHER]'SELECT $strProperties FROM $strSLS').Get() | select -Expand Properties -EA 0"
#iex $_qr
gwmi $strSLS $strProperties | select -Expand Properties -EA 0 | foreach {if (-not [String]::IsNullOrEmpty($_.Value)) {set $_.Name $_.Value -Scope script}}
}

function QueryProduct($strSLP, $strID, $strProperties)
{
#$_qr = "(([WMISEARCHER]'SELECT $strProperties FROM $strSLP WHERE ID=''$strID''').Get()).Properties | foreach {if ($null -NE $_.Value -And $_.Value -NE '') $_.Name+'='+$_.Value}}"
#$_qr = "([WMISEARCHER]'SELECT $strProperties FROM $strSLP WHERE ID=''$strID''').Get() | select -Expand Properties -EA 0"
#iex $_qr
gwmi $strSLP $strProperties -Filter "ID='$strID'" | select -Expand Properties -EA 0 | foreach {if (-not [String]::IsNullOrEmpty($_.Value)) {set $_.Name $_.Value -Scope script}}
}

function DetectSubscription {
if ($null -EQ $SubscriptionType -Or $SubscriptionType -EQ 120) {return}
if ($SubscriptionType -EQ 1) {
$SubMsgType = "Device based"
} else {
$SubMsgType = "User based"
}
if ($SubscriptionStatus -EQ 120) {
$SubMsgStatus = "Expired"
} elseif ($SubscriptionStatus -EQ 100) {
$SubMsgStatus = "Disabled"
} elseif ($SubscriptionStatus -EQ 1) {
$SubMsgStatus = "Active"
} else {
$SubMsgStatus = "Not active"
}
$SubMsgExpiry = "Unknown"
if ($SubscriptionExpiry) {
if ($SubscriptionExpiry.Contains("unspecified") -EQ $false) {$SubMsgExpiry = $SubscriptionExpiry}
}
$SubMsgEdition = "Unknown"
if ($SubscriptionEdition) {
if ($SubscriptionEdition.Contains("UNKNOWN") -EQ $false) {$SubMsgEdition = $SubscriptionEdition}
}
}

function OutputSubscription {
if ($null -EQ $SubscriptionType -Or $SubscriptionType -EQ 120) {return}
Write-Host
Write-Host "Subscription edition: $SubMsgEdition"
Write-Host "Subscription type   : $SubMsgType"
Write-Host "Subscription status : $SubMsgStatus"
Write-Host "Subscription expiry : $SubMsgExpiry"
}

function GetResult($strSLP, $strSLS, $strID, $strProperties)
{

$wspp_get -split ',' | foreach {set $_ $null -Scope script}
($wsps_get + ",ClientMachineID,KeyManagementServiceHostCaching") -split ',' | foreach {set $_ $null -Scope script}
"cKmsClient,cTblClient,cAvmClient,ExpireMsg,_xpr" -split ',' | foreach {set $_ $null -Scope script}

. QueryProduct $strSLP $strID $strProperties

if ($Description | Select-String "VOLUME_KMSCLIENT") {$cKmsClient = 1; $_mTag = "Volume"}
if ($Description | Select-String "TIMEBASED_") {$cTblClient = 1; $_mTag = "Timebased"}
if ($Description | Select-String "VIRTUAL_MACHINE_ACTIVATION") {$cAvmClient = 1; $_mTag = "Automatic VM"}

$_gpr = [Math]::Round($GracePeriodRemaining/1440)
if ($_gpr -GE 1) {
$_xpr = [DateTime]::Now.addMinutes($GracePeriodRemaining).ToString('yyyy-MM-dd hh:mm:ss tt')
}

$LicenseReason = '0x{0:X}' -f $LicenseStatusReason
$LicenseMsg = "Time remaining: $GracePeriodRemaining minute(s) ($_gpr day(s))"
if ($LicenseStatus -EQ 0) {
$LicenseInf = "Unlicensed"
$LicenseMsg = $null
}
if ($LicenseStatus -EQ 1) {
$LicenseInf = "Licensed"
$LicenseMsg = $null
if ($GracePeriodRemaining -EQ 0) {
    if ($winID) {$ExpireMsg = "The machine is permanently activated."} else {$ExpireMsg = "The product is permanently activated."}
    } else {
    $LicenseMsg = "$_mTag activation expiration: $GracePeriodRemaining minute(s) ($_gpr day(s))"
    if ($null -NE $_xpr) {$ExpireMsg = "$_mTag activation will expire $_xpr"}
    }
}
if ($LicenseStatus -EQ 2) {
$LicenseInf = "Initial grace period"
if ($null -NE $_xpr) {$ExpireMsg = "Initial grace period ends $_xpr"}
}
if ($LicenseStatus -EQ 3) {
$LicenseInf = "Additional grace period (KMS license expired or hardware out of tolerance)"
if ($null -NE $_xpr) {$ExpireMsg = "Additional grace period ends $_xpr"}
}
if ($LicenseStatus -EQ 4) {
$LicenseInf = "Non-genuine grace period"
if ($null -NE $_xpr) {$ExpireMsg = "Non-genuine grace period ends $_xpr"}
}
if ($LicenseStatus -EQ 6) {
$LicenseInf = "Extended grace period"
if ($null -NE $_xpr) {$ExpireMsg = "Extended grace period ends $_xpr"}
}
if ($LicenseStatus -EQ 5) {
$LicenseInf = "Notification"
$LicenseMsg = "Notification Reason: $LicenseReason"
    if ($LicenseReason -EQ "0xC004F200") {$LicenseMsg = $LicenseMsg + " (non-genuine)."
    } elseif ($LicenseReason -EQ "0xC004F009") {$LicenseMsg = $LicenseMsg + " (grace time expired)."
    }
}
if ($LicenseStatus -GT 6) {
$LicenseInf = "Unknown"
$LicenseMsg = $null
}

if ($winID -And $cSub) {
. QueryService $strSLS $wsps_get
. DetectSubscription
}

if ($null -EQ $cKmsClient) {return}

if ($KeyManagementServicePort -EQ 0) {$KeyManagementServicePort = 1688}
if ([String]::IsNullOrEmpty($KeyManagementServiceMachine)) {
$KmsReg = $null
} else {
$KmsReg = "Registered KMS machine name: ${KeyManagementServiceMachine}:${KeyManagementServicePort}"
}

if ($DiscoveredKeyManagementServiceMachinePort -EQ 0) {$DiscoveredKeyManagementServiceMachinePort = 1688}
if ([String]::IsNullOrEmpty($DiscoveredKeyManagementServiceMachineName)) {
$KmsDns = "DNS auto-discovery: KMS name not available"
} else {
$KmsDns = "KMS machine name from DNS: ${DiscoveredKeyManagementServiceMachineName}:${DiscoveredKeyManagementServiceMachinePort}"
}

. QueryService $strSLS "ClientMachineID,KeyManagementServiceHostCaching"

if ($KeyManagementServiceHostCaching -EQ "TRUE") {
$KeyManagementServiceHostCaching = "Enabled"
} else {
$KeyManagementServiceHostCaching = "Disabled"
}

if ($winbuild -GE 9600) {
if ([String]::IsNullOrEmpty($DiscoveredKeyManagementServiceMachineIpAddress)) {$DiscoveredKeyManagementServiceMachineIpAddress = "not available"}
}

}

function OutputResult
{
Write-Host
Write-Host "Name: $Name"
Write-Host "Description: $Description"
Write-Host "Activation ID: $ID"
Write-Host "Extended PID: $ProductKeyID"
if ($null -NE $ProductKeyChannel) {Write-Host "Product Key Channel: $ProductKeyChannel"}
Write-Host "Partial Product Key: $PartialProductKey"
Write-Host "License Status: $LicenseInf"
if ($null -NE $LicenseMsg) {Write-Host "$LicenseMsg"}
if ($LicenseStatus -NE 0 -And $EvaluationEndDate.Substring(0,8) -NE "16010101") {
$EED = [DateTime]::Parse([Management.ManagementDateTimeConverter]::ToDateTime($EvaluationEndDate),$null,48).ToString('yyyy-MM-dd hh:mm:ss tt')
Write-Host "Evaluation End Date: $EED UTC"
}
if ($null -EQ $cKmsClient) {
if ($null -NE $ExpireMsg) {Write-Host; Write-Host "    $ExpireMsg"}
OutputSubscription
return
}
if ($null -NE $VLActivationTypeEnabled) {Write-Host "Configured Activation Type: $($VLActTypes[$VLActivationTypeEnabled])"}
Write-Host
if ($LicenseStatus -NE 1) {
Write-Host "Please activate the product in order to update KMS client information values."
OutputSubscription
return
}
Write-Host "Most recent activation information:"
Write-Host "Key Management Service client information"
Write-Host "    Client Machine ID (CMID): $ClientMachineID"
if ($null -EQ $KmsReg) {
Write-Host "    $KmsDns"
Write-Host "    Registered KMS machine name: KMS name not available"
} else {
Write-Host "    $KmsReg"
}
if ($null -NE $DiscoveredKeyManagementServiceMachineIpAddress) {Write-Host "    KMS machine IP address: $DiscoveredKeyManagementServiceMachineIpAddress"}
Write-Host "    KMS machine extended PID: $KeyManagementServiceProductKeyID"
Write-Host "    Activation interval: $VLActivationInterval minutes"
Write-Host "    Renewal interval: $VLRenewalInterval minutes"
Write-Host "    KMS host caching: $KeyManagementServiceHostCaching"
if (-not [String]::IsNullOrEmpty($KeyManagementServiceLookupDomain)) {Write-Host "    KMS SRV record lookup domain: $KeyManagementServiceLookupDomain"}
if ($null -NE $ExpireMsg) {Write-Host; Write-Host "    $ExpireMsg"}
OutputSubscription

}

function echoOffice
{
if ($doMSG -EQ 1) {
Write-Host "$line2"
Write-Host "***                   Office Status                      ***"
Write-Host "$line2"
}
$script:doMSG = 0
}

#region vNextDiag
if ($PSVersionTable.PSVersion.Major -Lt 3)
{
	function ConvertFrom-Json
	{
		[CmdletBinding()]
		Param(
			[Parameter(ValueFromPipeline=$true)][Object]$item
		)
		[void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
		$psjs = New-Object System.Web.Script.Serialization.JavaScriptSerializer
		Return ,$psjs.DeserializeObject($item)
	}
	function ConvertTo-Json
	{
		[CmdletBinding()]
		Param(
			[Parameter(ValueFromPipeline=$true)][Object]$item
		)
		[void][System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
		$psjs = New-Object System.Web.Script.Serialization.JavaScriptSerializer
		Return $psjs.Serialize($item)
	}
}

function PrintModePerPridFromRegistry
{
	$vNextRegkey = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing\LicensingNext"
	$vNextPrids = Get-Item -Path $vNextRegkey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'property' | Where-Object -FilterScript {$_.ToLower() -like "*retail" -or $_.ToLower() -like "*volume"}
	If ($null -Eq $vNextPrids)
	{
		Write-Host
		Write-Host "No registry keys found."
		Return
	}
	Write-Host
	$vNextPrids | ForEach `
	{
		$mode = (Get-ItemProperty -Path $vNextRegkey -Name $_).$_
		Switch ($mode)
		{
			2 { $mode = "vNext"; Break }
			3 { $mode = "Device"; Break }
			Default { $mode = "Legacy"; Break }
		}
		Write-Host $_ = $mode
	}
}

function PrintSharedComputerLicensing
{
	$scaRegKey = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
	$scaValue = Get-ItemProperty -Path $scaRegKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "SharedComputerLicensing" -ErrorAction SilentlyContinue
	$scaRegKey2 = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing"
	$scaValue2 = Get-ItemProperty -Path $scaRegKey2 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "SharedComputerLicensing" -ErrorAction SilentlyContinue
	$scaPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Licensing"
	$scaPolicyValue = Get-ItemProperty -Path $scaPolicyKey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "SharedComputerLicensing" -ErrorAction SilentlyContinue
	If ($null -Eq $scaValue -And $null -Eq $scaValue2 -And $null -Eq $scaPolicyValue)
	{
		Write-Host
		Write-Host "No registry keys found."
		Return
	}
	$scaModeValue = $scaValue -Or $scaValue2 -Or $scaPolicyValue
	If ($scaModeValue -Eq 0)
	{
		$scaMode = "Disabled"
	}
	If ($scaModeValue -Eq 1)
	{
		$scaMode = "Enabled"
	}
	Write-Host
	Write-Host "Status:" $scaMode
	Write-Host
	$tokenFiles = $null
	$tokenPath = "${env:LOCALAPPDATA}\Microsoft\Office\16.0\Licensing"
	If (Test-Path $tokenPath)
	{
		$tokenFiles = Get-ChildItem -Path $tokenPath -Filter "*authString*" -Recurse | Where-Object { !$_.PSIsContainer }
	}
	If ($null -Eq $tokenFiles)
	{
		Write-Host "No tokens found."
		Return
	}
	If ($tokenFiles.Length -Eq 0)
	{
		Write-Host "No tokens found."
		Return
	}
	$tokenFiles | ForEach `
	{
		$tokenParts = (Get-Content -Encoding Unicode -Path $_.FullName).Split('_')
		$output = New-Object PSObject
		$output | Add-Member 8 'ACID' $tokenParts[0];
		$output | Add-Member 8 'User' $tokenParts[3];
		$output | Add-Member 8 'NotBefore' $tokenParts[4];
		$output | Add-Member 8 'NotAfter' $tokenParts[5];
		Write-Output $output
	}
}

function PrintLicensesInformation
{
	Param(
		[ValidateSet("NUL", "Device")]
		[String]$mode
	)
	If ($mode -Eq "NUL")
	{
		$licensePath = "${env:LOCALAPPDATA}\Microsoft\Office\Licenses"
	}
	ElseIf ($mode -Eq "Device")
	{
		$licensePath = "${env:PROGRAMDATA}\Microsoft\Office\Licenses"
	}
	$licenseFiles = $null
	If (Test-Path $licensePath)
	{
		$licenseFiles = Get-ChildItem -Path $licensePath -Recurse | Where-Object { !$_.PSIsContainer }
	}
	If ($null -Eq $licenseFiles)
	{
		Write-Host
		Write-Host "No licenses found."
		Return
	}
	If ($licenseFiles.Length -Eq 0)
	{
		Write-Host
		Write-Host "No licenses found."
		Return
	}
	$licenseFiles | ForEach `
	{
		$license = (Get-Content -Encoding Unicode $_.FullName | ConvertFrom-Json).License
		$decodedLicense = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($license)) | ConvertFrom-Json
		$licenseType = $decodedLicense.LicenseType
		If ($null -Ne $decodedLicense.ExpiresOn)
		{
			$expiry = [System.DateTime]::Parse($decodedLicense.ExpiresOn, $null, 'AdjustToUniversal')
		}
		Else
		{
			$expiry = New-Object DateTime
		}
		$licenseState = "Grace"
		If ((Get-Date) -Gt (Get-Date $decodedLicense.Metadata.NotAfter))
		{
			$licenseState = "RFM"
		}
		ElseIf ((Get-Date) -Lt (Get-Date $expiry))
		{
			$licenseState = "Licensed"
		}
		$output = New-Object PSObject
		$output | Add-Member 8 'File' $_.PSChildName;
		$output | Add-Member 8 'Version' $_.Directory.Name;
		$output | Add-Member 8 'Type' "User|${licenseType}";
		$output | Add-Member 8 'Product' $decodedLicense.ProductReleaseId;
		$output | Add-Member 8 'Acid' $decodedLicense.Acid;
		If ($mode -Eq "Device") { $output | Add-Member 8 'DeviceId' $decodedLicense.Metadata.DeviceId; }
		$output | Add-Member 8 'LicenseState' $licenseState;
		$output | Add-Member 8 'EntitlementStatus' $decodedLicense.Status;
		$output | Add-Member 8 'EntitlementExpiration' ("N/A", $decodedLicense.ExpiresOn)[!($null -eq $decodedLicense.ExpiresOn)];
		$output | Add-Member 8 'ReasonCode' ("N/A", $decodedLicense.ReasonCode)[!($null -eq $decodedLicense.ReasonCode)];
		$output | Add-Member 8 'NotBefore' $decodedLicense.Metadata.NotBefore;
		$output | Add-Member 8 'NotAfter' $decodedLicense.Metadata.NotAfter;
		$output | Add-Member 8 'NextRenewal' $decodedLicense.Metadata.RenewAfter;
		$output | Add-Member 8 'TenantId' ("N/A", $decodedLicense.Metadata.TenantId)[!($null -eq $decodedLicense.Metadata.TenantId)];
		#$output.PSObject.Properties | % { $ht = @{} } { $ht[$_.Name] = $_.Value } { $output = $ht | ConvertTo-Json }
		Write-Output $output
	}
}

function vNextDiagRun
{
$fNUL = ([IO.Directory]::Exists("${env:LOCALAPPDATA}\Microsoft\Office\Licenses")) -and ([IO.Directory]::GetFiles("${env:LOCALAPPDATA}\Microsoft\Office\Licenses", "*", 1).Length -GE 0)
$fDev = ([IO.Directory]::Exists("${env:PROGRAMDATA}\Microsoft\Office\Licenses")) -and ([IO.Directory]::GetFiles("${env:PROGRAMDATA}\Microsoft\Office\Licenses", "*", 1).Length -GE 0)
$rPID = $null -NE (GP "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing\LicensingNext" -EA 0 | select -Expand 'property' | where -Filter {$_.ToLower() -like "*retail" -or $_.ToLower() -like "*volume"})
$rSCA = $null -NE (GP "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -EA 0 | select -Expand "SharedComputerLicensing" -EA 0)
$rSCL = $null -NE (GP "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing" -EA 0 | select -Expand "SharedComputerLicensing" -EA 0)
[bool]$vNextRun = $fNUL -Or $fDev -Or $rPID -Or $rSCA -Or $rSCL

if ($vNextRun) {
Write-Host "$line2"
Write-Host "***                  Office vNext Status                 ***"
Write-Host "$line2"
Write-Host
Write-Host "========== Mode per ProductReleaseId =========="
PrintModePerPridFromRegistry
Write-Host
Write-Host "========== Shared Computer Licensing =========="
PrintSharedComputerLicensing
Write-Host
Write-Host "========== vNext licenses ==========="
PrintLicensesInformation -Mode "NUL"
Write-Host
Write-Host "========== Device licenses =========="
PrintLicensesInformation -Mode "Device"
Write-Host "$line3"
Write-Host
}

}
#endregion

$Host.UI.RawUI.WindowTitle = "Check Activation Status"
UnQuickEdit

$SysPath = "$env:SystemRoot\System32"
$env:Path = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0\"
if (Test-Path "$env:SystemRoot\Sysnative\reg.exe") {
$SysPath = "$env:SystemRoot\Sysnative"
$env:Path = "$env:SystemRoot\Sysnative;$env:SystemRoot;$env:SystemRoot\Sysnative\Wbem;$env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\;${env:Path}"
}

$wslp = "SoftwareLicensingProduct"
$wsls = "SoftwareLicensingService"
$oslp = "OfficeSoftwareProtectionProduct"
$osls = "OfficeSoftwareProtectionService"
$winApp = "55c92734-d682-4d71-983e-d6ec3f16059f"
$o14App = "59a52881-a989-479d-af46-f275c6370663"
$o15App = "0ff1ce15-a989-479d-af46-f275c6370663"
'cW1nd0ws', 'c0ff1ce15', 'ospp14', 'ospp15' | % {set $_ $null}
$wspp_get = "Description,DiscoveredKeyManagementServiceMachineName,DiscoveredKeyManagementServiceMachinePort,EvaluationEndDate,GracePeriodRemaining,ID,KeyManagementServiceMachine,KeyManagementServicePort,KeyManagementServiceProductKeyID,LicenseStatus,LicenseStatusReason,Name,PartialProductKey,ProductKeyID,VLActivationInterval,VLRenewalInterval"
$ospp_get = $wspp_get
if ($winbuild -GE 9200) {
$wspp_get = $wspp_get + ",KeyManagementServiceLookupDomain,VLActivationTypeEnabled"
}
if ($winbuild -GE 9600) {
$wspp_get = $wspp_get + ",DiscoveredKeyManagementServiceMachineIpAddress,ProductKeyChannel"
}
$wsps_get = "SubscriptionType,SubscriptionStatus,SubscriptionEdition,SubscriptionExpiry"
$VLActTypes = @("All", "AD", "KMS", "Token")
$sls = Select-String -Path "$SysPath\wbem\sppwmi.mof" -Encoding unicode -Pattern "SubscriptionType"
$cSub = ($winbuild -GE 19041) -And ($null -NE $sls)

$OsppHook = 1
try {gsv osppsvc -EA 1} catch {$OsppHook = 0}

try {sasv sppsvc -EA 1} catch {}
if ((DetectPKey $wslp $winApp)) {$cW1nd0ws = 1}
if ($winbuild -GE 9200) {
if ((DetectPKey $wslp $o15App)) {$c0ff1ce15 = 1}
}
if ($OsppHook -NE 0) {
try {sasv osppsvc -EA 1} catch {}
if ((DetectPKey $oslp $o14App)) {$ospp14 = 1}
if ($winbuild -LT 9200) {
if ((DetectPKey $oslp $o15App)) {$ospp15 = 1}
}
}

Write-Host "$line2"
Write-Host "***                   Windows Status                     ***"
Write-Host "$line2"
$winID = $true
if ($null -NE $cW1nd0ws)
{
GetID $wslp $winApp | foreach -EA 1 {
    . GetResult $wslp $wsls $_ $wspp_get
    OutputResult
    Write-Host "$line3"
    Write-Host
    }
}
else
{
Write-Host
Write-Host "Error: product key not found."
}

$winID = $false
$doMSG = 1
if ($null -NE $c0ff1ce15)
{
echoOffice
GetID $wslp $o15App | foreach -EA 1 {
    . GetResult $wslp $wsls $_ $wspp_get
    OutputResult
    Write-Host "$line3"
    Write-Host
    }
}

if ($null -NE $ospp15)
{
echoOffice
GetID $oslp $o15App | foreach -EA 1 {
    . GetResult $oslp $osls $_ $ospp_get
    OutputResult
    Write-Host "$line3"
    Write-Host
    }
}

if ($null -NE $ospp14)
{
echoOffice
GetID $oslp $o14App | foreach -EA 1 {
    . GetResult $oslp $osls $_ $ospp_get
    OutputResult
    Write-Host "$line3"
    Write-Host
    }
}

vNextDiagRun

ExitScript
