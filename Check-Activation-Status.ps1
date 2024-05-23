param (
    [Parameter()]
    [switch]
    $All,
    [Parameter()]
    [switch]
    $IID
)

function ExitScript($ExitCode = 0)
{
	if (!$psISE) {
		Read-Host "`r`nPress Enter to exit" | Out-Null
	}
	Exit $ExitCode
}

if (-Not $PSVersionTable) {
	Write-Host "==== ERROR ====`r`n"
	Write-Host 'Windows PowerShell 1.0 is not supported by this script.'
	ExitScript 1
}

if ($ExecutionContext.SessionState.LanguageMode.value__ -NE 0) {
	Write-Host "==== ERROR ====`r`n"
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
	Write-Host "==== ERROR ====`r`n"
	Write-Host 'This build of Windows is not supported by this script.'
	ExitScript 1
}

$line2 = "============================================================"
$line3 = "____________________________________________________________"

function echoWindows
{
	Write-Host "$line2"
	Write-Host "===                   Windows Status                     ==="
	Write-Host "$line2"
	if (!$All.IsPresent) {Write-Host}
}

function echoOffice
{
	if ($doMSG -EQ 0) {return}
	Write-Host "$line2"
	Write-Host "===                   Office Status                      ==="
	Write-Host "$line2"
	if (!$All.IsPresent) {Write-Host}
	$script:doMSG = 0
}

function strGetRegistry($strKey, $strName)
{
Get-ItemProperty -EA 0 $strKey | select -EA 0 -Expand $strName
}

function CheckOhook
{
	$ohook = 0
	$paths = "${env:ProgramFiles}", "${env:ProgramW6432}", "${env:ProgramFiles(x86)}"

	15, 16 | ForEach `
	{
		$A = $_; $paths | ForEach `
		{
			if (Test-Path "$($_)$('\Microsoft Office\Office')$($A)$('\sppc*dll')") {$ohook = 1}
		}
	}

	"System", "SystemX86" | ForEach `
	{
		$A = $_; "Office 15", "Office" | ForEach `
		{
			$B = $_; $paths | ForEach `
			{
				if (Test-Path "$($_)$('\Microsoft ')$($B)$('\root\vfs\')$($A)$('\sppc*dll')") {$ohook = 1}
			}
		}
	}

	if ($ohook -EQ 0) {
		return
	}

	Write-Host "$line2"
	Write-Host "===                Office Ohook Status                   ==="
	Write-Host "$line2"
	Write-Host
	Write-Host -back 'Black' -fore 'Yellow' 'Ohook for permanent Office activation is installed.'
	Write-Host -back 'Black' -fore 'Yellow' 'You can ignore the below mentioned Office activation status.'
	Write-Host
}

#region WMI
function DetectID($strSLP, $strAppId, $strProperty = "ID")
{
	$bReturn = $false
	$fltr = "ApplicationID='$strAppId'"
	if (!$All.IsPresent) {
		$fltr = $fltr + " AND PartialProductKey <> NULL"
	}
	Get-WmiObject $strSLP $strProperty -Filter $fltr -EA 0 | select $strProperty -EA 0 | foreach {
		$bReturn = $true
	}
	return $bReturn
}

function GetID($strSLP, $strAppId, $strProperty = "ID")
{
	$IDs = [Collections.ArrayList]@()
	if ($All.IsPresent) {
		Get-WmiObject $strSLP $strProperty -Filter "ApplicationID='$strAppId' AND PartialProductKey IS NULL AND LicenseDependsOn <> NULL" -EA 0 | select -Expand $strProperty -EA 0 | foreach {$IDs += $_}
		Get-WmiObject $strSLP $strProperty -Filter "ApplicationID='$strAppId' AND PartialProductKey IS NULL AND LicenseDependsOn IS NULL" -EA 0 | select -Expand $strProperty -EA 0 | foreach {$IDs += $_}
	}
	Get-WmiObject $strSLP $strProperty -Filter "ApplicationID='$strAppId' AND PartialProductKey <> NULL AND LicenseDependsOn <> NULL" -EA 0 | select -Expand $strProperty -EA 0 | foreach {$IDs += $_}
	Get-WmiObject $strSLP $strProperty -Filter "ApplicationID='$strAppId' AND PartialProductKey <> NULL AND LicenseDependsOn IS NULL" -EA 0 | select -Expand $strProperty -EA 0 | foreach {$IDs += $_}
	return $IDs
}

function QueryService($strSLS, $strProperties)
{
	Get-WmiObject $strSLS $strProperties -EA 0 | select -Expand Properties -EA 0 | foreach {
		if (-Not [String]::IsNullOrEmpty($_.Value)) {set $_.Name $_.Value -Scope script}
	}
}

function QueryProduct($strSLP, $strID, $strProperties)
{
	Get-WmiObject $strSLP $strProperties -Filter "ID='$strID'" -EA 0 | select -Expand Properties -EA 0 | foreach {
		if (-Not [String]::IsNullOrEmpty($_.Value)) {set $_.Name $_.Value -Scope script}
	}
}

function DetectSubscription {
	if ($null -EQ $SubscriptionType -Or $SubscriptionType -EQ 120) {
		return
	}
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
	if ($null -EQ $SubscriptionType -Or $SubscriptionType -EQ 120) {
		return
	}
	Write-Host
	Write-Host "Subscription information:"
	Write-Host "    Edition: $SubMsgEdition"
	Write-Host "    Type   : $SubMsgType"
	Write-Host "    Status : $SubMsgStatus"
	Write-Host "    Expiry : $SubMsgExpiry"
}

function DetectKmsHost
{
	if (($winID -And $winbuild -LT 7600) -EQ $false) {
		. QueryService $strSLS "KeyManagementServiceListeningPort,KeyManagementServiceDnsPublishing,KeyManagementServiceLowPriority"
		. QueryProduct $strSLP $strID $wkms_get
	} else {
		. QueryService $strSLS $wkms_get
		$KeyManagementServiceListeningPort = strGetRegistry $SLKeyPath "KeyManagementServiceListeningPort"
		$KeyManagementServiceDnsPublishing = strGetRegistry $SLKeyPath "DisableDnsPublishing"
		$KeyManagementServiceLowPriority = strGetRegistry $SLKeyPath "EnableKmsLowPriority"
		if (-Not $KeyManagementServiceDnsPublishing) {$KeyManagementServiceDnsPublishing = "TRUE"}
		if (-Not $KeyManagementServiceLowPriority) {$KeyManagementServiceLowPriority = "FALSE"}
	}

	if (-Not $KeyManagementServiceListeningPort) {$KeyManagementServiceListeningPort = 1688}
	if ($KeyManagementServiceDnsPublishing -EQ "TRUE") {
		$KeyManagementServiceDnsPublishing = "Enabled"
	} else {
		$KeyManagementServiceDnsPublishing = "Disabled"
	}
	if ($KeyManagementServiceLowPriority -EQ "TRUE") {
		$KeyManagementServiceLowPriority = "Low"
	} else {
		$KeyManagementServiceLowPriority = "Normal"
	}
}

function GetResult($strSLP, $strSLS, $strID, $strProperties)
{

	$wspp_get -split ',' | foreach {set $_ $null -Scope script}
	($wsps_get + "," + $wsls_get + "," + $osls_get) -split ',' | foreach {set $_ $null -Scope script}
	"cKmsHost,cKmsClient,cTblClient,cAvmClient,ExpireMsg,_xpr,ProductKeyChannel" -split ',' | foreach {set $_ $null -Scope script}

	. QueryProduct $strSLP $strID $strProperties

	if ($Description | Select-String "VOLUME_KMSCLIENT") {$cKmsClient = 1; $_mTag = "Volume"}
	if ($Description | Select-String "TIMEBASED_") {$cTblClient = 1; $_mTag = "Timebased"}
	if ($Description | Select-String "VIRTUAL_MACHINE_ACTIVATION") {$cAvmClient = 1; $_mTag = "Automatic VM"}
	if ($null -EQ $cKmsClient) {
		if ($Description | Select-String "VOLUME_KMS") {$cKmsHost = 1}
	}

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
			if ($winID -And -Not $LicenseIsAddon) {$ExpireMsg = "The machine is permanently activated."} else {$ExpireMsg = "The product is permanently activated."}
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
	if ($LicenseStatus -EQ 5) {
		$LicenseInf = "Notification"
		$LicenseMsg = "Notification Reason: $LicenseReason"
		if ($LicenseReason -EQ "0xC004F200") {$LicenseMsg = $LicenseMsg + " (non-genuine)."}
		if ($LicenseReason -EQ "0xC004F009") {$LicenseMsg = $LicenseMsg + " (grace time expired)."}
	}
	if ($LicenseStatus -GT 5) {
		$LicenseInf = "Unknown"
		$LicenseMsg = $null
	}
	if ($LicenseStatus -EQ 6 -And $winbuild -GE 7600) {
		$LicenseInf = "Extended grace period"
		if ($null -NE $_xpr) {$ExpireMsg = "Extended grace period ends $_xpr"}
	}

	if ($winID -And $cSub -And -Not $LicenseIsAddon) {
		. QueryService $strSLS $wsps_get
		. DetectSubscription
	}

	if ($winID -And $winbuild -LT 9600 -And $PartialProductKey -And -Not $LicenseIsAddon) {
		$dp4 = Get-ItemProperty -EA 0 "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | select -EA 0 -Expand DigitalProductId4
		if ($null -NE $dp4) {
			$ProductKeyChannel = ([System.Text.Encoding]::Unicode.GetString($dp4, 1016, 128)).Trim([char]$null)
		}
	}

	if ($null -EQ $cKmsClient -And $null -EQ $cKmsHost) {
		return
	}

	if ($null -EQ $PartialProductKey) {
		return
	}

	if ($strSLS -EQ $wsls) {
		. QueryService $strSLS $wsls_get
	} else {
		. QueryService $strSLS $osls_get
	}

	if ($null -NE $cKmsHost) {
		if ($IsKeyManagementServiceMachine -GT 0) {
			. DetectKmsHost
		} else {
			set cKmsHost $null -Scope script
		}
		return
	}

	if ($winID -And $winbuild -LT 7600) {
		$KeyManagementServicePort = strGetRegistry $SLKeyPath "KeyManagementServicePort"
		$DiscoveredKeyManagementServiceMachineName = strGetRegistry $NSKeyPath "DiscoveredKeyManagementServiceName"
		$DiscoveredKeyManagementServiceMachinePort = strGetRegistry $NSKeyPath "DiscoveredKeyManagementServicePort"
	}

	if ([String]::IsNullOrEmpty($KeyManagementServiceMachine)) {
		$KmsReg = $null
	} else {
		if (-Not $KeyManagementServicePort) {$KeyManagementServicePort = 1688}
		$KmsReg = "Registered KMS machine name: ${KeyManagementServiceMachine}:${KeyManagementServicePort}"
	}

	if ([String]::IsNullOrEmpty($DiscoveredKeyManagementServiceMachineName)) {
		$KmsDns = "DNS auto-discovery: KMS name not available"
		if ($null -NE $Vista) {$KmsDns = $Vista}
	} else {
		if (-Not $DiscoveredKeyManagementServiceMachinePort) {$DiscoveredKeyManagementServiceMachinePort = 1688}
		$KmsDns = "KMS machine name from DNS: ${DiscoveredKeyManagementServiceMachineName}:${DiscoveredKeyManagementServiceMachinePort}"
	}

	if ($null -NE $KeyManagementServiceHostCaching) {
		if ($KeyManagementServiceHostCaching -EQ "TRUE") {
			$KeyManagementServiceHostCaching = "Enabled"
		} else {
			$KeyManagementServiceHostCaching = "Disabled"
		}
	}

	if ($strSLS -EQ $wsls -And $winbuild -GE 9600) {
		if ([String]::IsNullOrEmpty($DiscoveredKeyManagementServiceMachineIpAddress)) {
			$DiscoveredKeyManagementServiceMachineIpAddress = "not available"
		}
	}

}

function OutputResult
{
	if ($All.IsPresent) {Write-Host}
	Write-Host "Name: $Name"
	Write-Host "Description: $Description"
	Write-Host "Activation ID: $ID"
	if ($null -NE $ProductKeyID) {Write-Host "Extended PID: $ProductKeyID"}
	if ($null -NE $OfflineInstallationId) {Write-Host "Installation ID: $OfflineInstallationId"}
	if ($null -NE $ProductKeyChannel) {Write-Host "Product Key Channel: $ProductKeyChannel"}
	if ($null -NE $PartialProductKey) {Write-Host "Partial Product Key: $PartialProductKey"} else {Write-Host "Product Key: Not installed"}
	Write-Host "License Status: $LicenseInf"
	if ($null -NE $LicenseMsg) {Write-Host "$LicenseMsg"}
	if ($LicenseStatus -NE 0 -And $EvaluationEndDate.Substring(0,4) -NE "1601") {
		$EED = [DateTime]::Parse([Management.ManagementDateTimeConverter]::ToDateTime($EvaluationEndDate),$null,48).ToString('yyyy-MM-dd hh:mm:ss tt')
		Write-Host "Evaluation End Date: $EED UTC"
	}
	if ($null -EQ $cKmsClient -And $null -EQ $cKmsHost) {
		if ($null -NE $ExpireMsg) {Write-Host; Write-Host "    $ExpireMsg"}
		return
	}
	if ($null -EQ $PartialProductKey) {
		return
	}
	if ($null -NE $cKmsHost) {
		Write-Host
		Write-Host "Key Management Service host information:"
		Write-Host "    Current count: $KeyManagementServiceCurrentCount"
		Write-Host "    Listening on Port: $KeyManagementServiceListeningPort"
		Write-Host "    DNS publishing: $KeyManagementServiceDnsPublishing"
		Write-Host "    KMS priority: $KeyManagementServiceLowPriority"
		if (-Not [String]::IsNullOrEmpty($KeyManagementServiceTotalRequests)) {
			Write-Host
			Write-Host "Key Management Service cumulative requests received from clients:"
			Write-Host "    Total: $KeyManagementServiceTotalRequests"
			Write-Host "    Failed: $KeyManagementServiceFailedRequests"
			Write-Host "    Unlicensed: $KeyManagementServiceUnlicensedRequests"
			Write-Host "    Licensed: $KeyManagementServiceLicensedRequests"
			Write-Host "    Initial grace period: $KeyManagementServiceOOBGraceRequests"
			Write-Host "    Expired or Hardware out of tolerance: $KeyManagementServiceOOTGraceRequests"
			Write-Host "    Non-genuine grace period: $KeyManagementServiceNonGenuineGraceRequests"
			Write-Host "    Notification: $KeyManagementServiceNotificationRequests"
		}
		return
	}
	if ($null -NE $VLActivationTypeEnabled) {Write-Host "Configured Activation Type: $($VLActTypes[$VLActivationTypeEnabled])"}
	Write-Host
	if ($LicenseStatus -NE 1) {
		Write-Host "Please activate the product in order to update KMS client information values."
		return
	}
	#Write-Host "Most recent activation information:"
	Write-Host "Key Management Service client information:"
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
	if ($null -NE $KeyManagementServiceHostCaching) {Write-Host "    KMS host caching: $KeyManagementServiceHostCaching"}
	if (-Not [String]::IsNullOrEmpty($KeyManagementServiceLookupDomain)) {Write-Host "    KMS SRV record lookup domain: $KeyManagementServiceLookupDomain"}
	if ($null -NE $ExpireMsg) {Write-Host; Write-Host "    $ExpireMsg"}
}
#endregion

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
	$vNextPrids = Get-Item -Path $vNextRegkey -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'property' -ErrorAction SilentlyContinue | Where-Object -FilterScript {$_.ToLower() -like "*retail" -or $_.ToLower() -like "*volume"}
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
			$expiry = New-Object System.DateTime
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
		#$output.PSObject.Properties | foreach { $ht = @{} } { $ht[$_.Name] = $_.Value } { $output = $ht | ConvertTo-Json }
		Write-Output $output
	}
}

function vNextDiagRun
{
	$fNUL = ([IO.Directory]::Exists("${env:LOCALAPPDATA}\Microsoft\Office\Licenses")) -and ([IO.Directory]::GetFiles("${env:LOCALAPPDATA}\Microsoft\Office\Licenses", "*", 1).Length -GE 0)
	$fDev = ([IO.Directory]::Exists("${env:PROGRAMDATA}\Microsoft\Office\Licenses")) -and ([IO.Directory]::GetFiles("${env:PROGRAMDATA}\Microsoft\Office\Licenses", "*", 1).Length -GE 0)
	$rPID = $null -NE (GP "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing\LicensingNext" -EA 0 | select -Expand 'property' -EA 0 | where -Filter {$_.ToLower() -like "*retail" -or $_.ToLower() -like "*volume"})
	$rSCA = $null -NE (GP "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -EA 0 | select -Expand "SharedComputerLicensing" -EA 0)
	$rSCL = $null -NE (GP "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing" -EA 0 | select -Expand "SharedComputerLicensing" -EA 0)

	if (($fNUL -Or $fDev -Or $rPID -Or $rSCA -Or $rSCL) -EQ $false) {
		Return
	}

	if ($All.IsPresent) {Write-Host}
	Write-Host "$line2"
	Write-Host "===                  Office vNext Status                 ==="
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
#endregion

#region clic

<#
;;; Powershell port: abbodi1406
;;; Source: https://github.com/asdcorp/clic

Copyright 2023 asdcorp

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the “Software”), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

function BoolToWStr($bVal) {
	("TRUE", "FALSE")[!$bVal]
}

function InitializePInvoke {
	$Marshal = [System.Runtime.InteropServices.Marshal]
	$Module = [AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 'Run').DefineDynamicModule((Get-Random))

	$Class = $Module.DefineType('NativeMethods', 'Public, Abstract, Sealed, BeforeFieldInit', [Object], 0)
	$Class.DefinePInvokeMethod('SLIsWindowsGenuineLocal', 'slc.dll', 'Public, Static', 'Standard', [Int32], @([UInt32].MakeByRefType()), 'Winapi', 'Unicode').SetImplementationFlags('PreserveSig')
	$Class.DefinePInvokeMethod('SLGetWindowsInformationDWORD', 'slc.dll', 22, 1, [Int32], @([String], [UInt32].MakeByRefType()), 1, 3).SetImplementationFlags(128)
	$Class.DefinePInvokeMethod('SLGetWindowsInformation', 'slc.dll', 22, 1, [Int32], @([String], [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()), 1, 3).SetImplementationFlags(128)

	if ($DllSubscription) {
		$Class.DefinePInvokeMethod('ClipGetSubscriptionStatus', 'Clipc.dll', 22, 1, [Int32], @([IntPtr].MakeByRefType()), 1, 3).SetImplementationFlags(128)
		$Struct = $Class.DefineNestedType('SubStatus', 'NestedPublic, SequentialLayout, Sealed, BeforeFieldInit', [ValueType], 0)
		[void]$Struct.DefineField('dwEnabled', [UInt32], 'Public')
		[void]$Struct.DefineField('dwSku', [UInt32], 6)
		[void]$Struct.DefineField('dwState', [UInt32], 6)
		$SubStatus = $Struct.CreateType()
	}

	$Win32 = $Class.CreateType()
}

function InitializeDigitalLicenseCheck {
	$CAB = [System.Reflection.Emit.CustomAttributeBuilder]

	$ICom = $Module.DefineType('EUM.IEUM', 'Public, Interface, Abstract, Import')
	$ICom.SetCustomAttribute($CAB::new([System.Runtime.InteropServices.ComImportAttribute].GetConstructor(@()), @()))
	$ICom.SetCustomAttribute($CAB::new([System.Runtime.InteropServices.GuidAttribute].GetConstructor(@([String])), @('F2DCB80D-0670-44BC-9002-CD18688730AF')))
	$ICom.SetCustomAttribute($CAB::new([System.Runtime.InteropServices.InterfaceTypeAttribute].GetConstructor(@([Int16])), @([Int16]1)))

	1..4 | % { [void]$ICom.DefineMethod('VF'+$_, 'Public, Virtual, HideBySig, NewSlot, Abstract', 'Standard, HasThis', [Void], @()) }
	[void]$ICom.DefineMethod('AcquireModernLicenseForWindows', 1478, 33, [Int32], @([Int32], [Int32].MakeByRefType()))

	$IEUM = $ICom.CreateType()
}

function PrintStateData {
	$pwszStateData = 0
	$cbSize = 0

	if ($Win32::SLGetWindowsInformation(
		"Security-SPP-Action-StateData",
		[ref]$null,
		[ref]$cbSize,
		[ref]$pwszStateData
	)) {
		return $FALSE
	}

	[string[]]$pwszStateString = $Marshal::PtrToStringUni($pwszStateData) -replace ";", "`r`n    "
	Write-Host "    $pwszStateString"

	$Marshal::FreeHGlobal($pwszStateData)
	return $TRUE
}

function PrintLastActivationHRresult {
	$pdwLastHResult = 0
	$cbSize = 0

	if ($Win32::SLGetWindowsInformation(
		"Security-SPP-LastWindowsActivationHResult",
		[ref]$null,
		[ref]$cbSize,
		[ref]$pdwLastHResult
	)) {
		return $FALSE
	}

	Write-Host ("    LastActivationHResult=0x{0:x8}" -f $Marshal::ReadInt32($pdwLastHResult))

	$Marshal::FreeHGlobal($pdwLastHResult)
	return $TRUE
}

function PrintIsWindowsGenuine {
	$dwGenuine = 0
	$ppwszGenuineStates = @(
		"SL_GEN_STATE_IS_GENUINE",
		"SL_GEN_STATE_INVALID_LICENSE",
		"SL_GEN_STATE_TAMPERED",
		"SL_GEN_STATE_OFFLINE",
		"SL_GEN_STATE_LAST"
	)

	if ($Win32::SLIsWindowsGenuineLocal([ref]$dwGenuine)) {
		return $FALSE
	}

	if ($dwGenuine -lt 5) {
		Write-Host ("    IsWindowsGenuine={0}" -f $ppwszGenuineStates[$dwGenuine])
	} else {
		Write-Host ("    IsWindowsGenuine={0}" -f $dwGenuine)
	}

	return $TRUE
}

function PrintDigitalLicenseStatus {
	try {
		. InitializeDigitalLicenseCheck
		$ComObj = New-Object -Com EditionUpgradeManagerObj.EditionUpgradeManager
	} catch {
		return $FALSE
	}

	$parameters = 1, $null

	if ([EUM.IEUM].GetMethod("AcquireModernLicenseForWindows").Invoke($ComObj, $parameters)) {
		return $FALSE
	}

	$dwReturnCode = $parameters[1]
	[bool]$bDigitalLicense = $FALSE

	$bDigitalLicense = (($dwReturnCode -ge 0) -and ($dwReturnCode -ne 1))
	Write-Host ("    IsDigitalLicense={0}" -f (BoolToWStr $bDigitalLicense))

	return $TRUE
}

function PrintSubscriptionStatus {
	$dwSupported = 0

	if ($winbuild -ge 15063) {
		$pwszPolicy = "ConsumeAddonPolicySet"
	} else {
		$pwszPolicy = "Allow-WindowsSubscription"
	}

	if ($Win32::SLGetWindowsInformationDWORD($pwszPolicy, [ref]$dwSupported)) {
		return $FALSE
	}

	Write-Host ("    SubscriptionSupportedEdition={0}" -f (BoolToWStr $dwSupported))

	$pStatus = $Marshal::AllocHGlobal($Marshal::SizeOf([Type]$SubStatus))
	if ($Win32::ClipGetSubscriptionStatus([ref]$pStatus)) {
		return $FALSE
	}

	$sStatus = [Activator]::CreateInstance($SubStatus)
	$sStatus = $Marshal::PtrToStructure($pStatus, [Type]$SubStatus)
	$Marshal::FreeHGlobal($pStatus)

	Write-Host ("    SubscriptionEnabled={0}" -f (BoolToWStr $sStatus.dwEnabled))

	if ($sStatus.dwEnabled -eq 0) {
		return $TRUE
	}

	Write-Host ("    SubscriptionSku={0}" -f $sStatus.dwSku)
	Write-Host ("    SubscriptionState={0}" -f $sStatus.dwState)

	return $TRUE
}

function ClicRun
{
	if ($All.IsPresent) {Write-Host}
	Write-Host "Client Licensing Check information:"

	$null = PrintStateData
	$null = PrintLastActivationHRresult
	$null = PrintIsWindowsGenuine

	if ($DllDigital) {
		$null = PrintDigitalLicenseStatus
	}

	if ($DllSubscription) {
		$null = PrintSubscriptionStatus
	}

	Write-Host "$line3"
	Write-Host
}
#endregion

function UnQuickEdit
{
	$t=[AppDomain]::CurrentDomain.DefineDynamicAssembly((Get-Random), 1).DefineDynamicModule((Get-Random), $False).DefineType((Get-Random))
	$t.DefinePInvokeMethod('GetStdHandle', 'kernel32.dll', 22, 1, [IntPtr], @([Int32]), 1, 3).SetImplementationFlags(128)
	$t.DefinePInvokeMethod('SetConsoleMode', 'kernel32.dll', 22, 1, [Boolean], @([IntPtr], [Int32]), 1, 3).SetImplementationFlags(128)
	$t.DefinePInvokeMethod('GetConsoleWindow', 'kernel32.dll', 22, 1, [IntPtr], @(), 1, 3).SetImplementationFlags(128)
	$t.DefinePInvokeMethod('SendMessageW', 'user32.dll', 22, 1, [IntPtr], @([IntPtr], [UInt32], [IntPtr], [IntPtr]), 1, 3).SetImplementationFlags(128)
	$k=$t.CreateType()
	if ($winbuild -GE 17763) {
		if ($k::SendMessageW($k::GetConsoleWindow(), 127, 0, 0) -EQ [IntPtr]::Zero) {
			return
		}
	}
	$v=(0x0080, 0x00A0)[!($winbuild -GE 10586)]
	$b=$k::SetConsoleMode($k::GetStdHandle(-10), $v)
}

$Admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Vista = $null
if ($winbuild -LT 7600 -And -Not $Admin) {
	$Vista = "DNS auto-discovery: Run the script as administrator to retrieve info"
}

$Host.UI.RawUI.WindowTitle = "Check Activation Status"
UnQuickEdit
if ($All.IsPresent) {
	$B=$Host.UI.RawUI.BufferSize;$B.Height=3000;$Host.UI.RawUI.BufferSize=$B;clear;
}

$SysPath = "$env:SystemRoot\System32"
if (Test-Path "$env:SystemRoot\Sysnative\reg.exe") {
	$SysPath = "$env:SystemRoot\Sysnative"
}

$wslp = "SoftwareLicensingProduct"
$wsls = "SoftwareLicensingService"
$oslp = "OfficeSoftwareProtectionProduct"
$osls = "OfficeSoftwareProtectionService"
$winApp = "55c92734-d682-4d71-983e-d6ec3f16059f"
$o14App = "59a52881-a989-479d-af46-f275c6370663"
$o15App = "0ff1ce15-a989-479d-af46-f275c6370663"
$wsls_get = "ClientMachineID,KeyManagementServiceHostCaching"
$wspp_get = "Description,DiscoveredKeyManagementServiceMachineName,DiscoveredKeyManagementServiceMachinePort,EvaluationEndDate,GracePeriodRemaining,ID,IsKeyManagementServiceMachine,KeyManagementServiceMachine,KeyManagementServicePort,KeyManagementServiceProductKeyID,LicenseIsAddon,LicenseStatus,LicenseStatusReason,Name,PartialProductKey,ProductKeyID,VLActivationInterval,VLRenewalInterval"
if ($IID.IsPresent) {
	$wspp_get = $wspp_get + ",OfflineInstallationId"
}
$ospp_get = $wspp_get
$osls_get = $wsls_get
if ($winbuild -GE 9200) {
	$wspp_get = $wspp_get + ",KeyManagementServiceLookupDomain,VLActivationTypeEnabled"
}
if ($winbuild -GE 9600) {
	$wspp_get = $wspp_get + ",DiscoveredKeyManagementServiceMachineIpAddress,ProductKeyChannel"
}
if ($winbuild -LT 7600) {
	$wspp_get = "Description,EvaluationEndDate,GracePeriodRemaining,ID,LicenseIsAddon,LicenseStatus,LicenseStatusReason,Name,PartialProductKey,ProductKeyID"
	$wsls_get = "ClientMachineID,IsKeyManagementServiceMachine,KeyManagementServiceMachine,KeyManagementServiceProductKeyID,VLActivationInterval,VLRenewalInterval"
	if ($IID.IsPresent) {$wspp_get = $wspp_get + ",OfflineInstallationId"}
}
$wkms_get = "KeyManagementServiceCurrentCount,KeyManagementServiceUnlicensedRequests,KeyManagementServiceLicensedRequests,KeyManagementServiceOOBGraceRequests,KeyManagementServiceOOTGraceRequests,KeyManagementServiceNonGenuineGraceRequests,KeyManagementServiceTotalRequests,KeyManagementServiceFailedRequests,KeyManagementServiceNotificationRequests"
$wsps_get = "SubscriptionType,SubscriptionStatus,SubscriptionEdition,SubscriptionExpiry"
$cSub = ($winbuild -GE 19041) -And (Select-String -Path "$SysPath\wbem\sppwmi.mof" -Encoding unicode -Pattern "SubscriptionType")
$DllDigital = ($winbuild -GE 10240) -And (Test-Path "$SysPath\EditionUpgradeManagerObj.dll")
$DllSubscription = ($winbuild -GE 14393) -And (Test-Path "$SysPath\Clipc.dll")
$VLActTypes = @("All", "AD", "KMS", "Token")
$SLKeyPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SL"
$NSKeyPath = "Registry::HKEY_USERS\S-1-5-20\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SL"

'cW1nd0ws', 'c0ff1ce15', 'ospp14', 'ospp15' | foreach {set $_ $null}

$OsppHook = 1
try {gsv osppsvc -EA 1 | Out-Null} catch {$OsppHook = 0}

if ($winbuild -GE 7600) {
	try {sasv sppsvc -EA 1} catch {}
}
else
{
	try {sasv slsvc -EA 1} catch {}
}

if ((DetectID $wslp $winApp)) {$cW1nd0ws = 1}

if ($winbuild -GE 9200) {
	if ((DetectID $wslp $o15App)) {$c0ff1ce15 = 1}
}

if ($OsppHook -NE 0) {
	try {sasv osppsvc -EA 1} catch {}

	if ((DetectID $oslp $o14App)) {$ospp14 = 1}

	if ($winbuild -LT 9200) {
		if ((DetectID $oslp $o15App)) {$ospp15 = 1}
	}
}

echoWindows

$winID = $true

if ($null -NE $cW1nd0ws)
{
	GetID $wslp $winApp | foreach -EA 1 {
	. GetResult $wslp $wsls $_ $wspp_get
	OutputResult
	OutputSubscription
	Write-Host "$line3"
	if (!$All.IsPresent) {Write-Host}
	}
}
else
{
	Write-Host
	Write-Host "Error: product key not found."
}

if ($winbuild -GE 9200) {
	. InitializePInvoke
	ClicRun
}

if ($c0ff1ce15 -Or $ospp15) {
	CheckOhook
}

$winID = $false
$doMSG = 1

if ($null -NE $c0ff1ce15) {
	echoOffice
	GetID $wslp $o15App | foreach -EA 1 {
	. GetResult $wslp $wsls $_ $wspp_get
	OutputResult
	Write-Host "$line3"
	if (!$All.IsPresent) {Write-Host}
	}
}

if ($null -NE $ospp15) {
	echoOffice
	GetID $oslp $o15App | foreach -EA 1 {
	. GetResult $oslp $osls $_ $ospp_get
	OutputResult
	Write-Host "$line3"
	if (!$All.IsPresent) {Write-Host}
	}
}

if ($null -NE $ospp14) {
	echoOffice
	GetID $oslp $o14App | foreach -EA 1 {
	. GetResult $oslp $osls $_ $ospp_get
	OutputResult
	Write-Host "$line3"
	if (!$All.IsPresent) {Write-Host}
	}
}

vNextDiagRun

ExitScript 0
