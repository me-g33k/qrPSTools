function psQRCLITools {
  <#
.SYNOPSIS
  A collection of handy Powershell QRadar API
.DESCRIPTION
	A collection of handy Powershell QRadar API. Set-QRCreds needs to be run before these can be used.
	
		close-bulkQROffenses
		Find-QRAsset
		Get-QRAssetInfo
		Get-QRAQL
		Get-QRWhois
		Load-QRNets
		Set-QRCreds
		Update-AssetProps
		
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
.EXAMPLE
	
	close-bulkQROffenses - Closes Offenses in supplied offenseId array
	Find-QRAsset - Searches for a QRadar asset using IP Address
	Get-QRAssetInfo - Retrieves QRadar Asset information
	Get-QRAQL - Retieves results from provided AQL
	Get-QRWhois - Uses QRadar to perform whois search
	Load-QRNets - Loads QRadar Network Heirarchy information
	Set-QRCreds - Sets login credentials for API Calls
	Update-AssetProps - Posts property changes to QRadar assets

#>
	
}

function setCWD {
<#
.SYNOPSIS
  Sets the Global CWD (if it doesn't already exist) variable used in many of the functions here.
.DESCRIPTION
  Sets the Global CWD variable used in many of the functions here.
.INPUTS
  None
.OUTPUTS
  Sets $Global:CWD
.NOTES
  Version:        $Rev$
  Author:         $Author$
  Creation Date:  $Date$
  Purpose/Change: Initial script development
  
.EXAMPLE
  This is only called internally by other functions in this bundle.
#>

If (-NOT $global:cwd) {

	If ($env:TEMP) {

		$global:cwd = $env:TEMP
	
	} else {

		$global:cwd = $env:TMP

		}

	}

}

Function Load-qrCLIConfig {
<#

.SYNOPSIS
  Loads Module Config settins from file.
.DESCRIPTION
  Loads configuration information from the qrCLITools_settings.json file.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development

.EXAMPLE
  Load-qrCLIConfig

#>
$configFile = "$psscriptroot\qrCLITools_settings.json"
filter timestamp {"$(Get-Date -Format G): $_"}
try {

	$qrCLIToolSettings = Get-Content $configFile -errorAction STOP | ConvertFrom-Json

	$msg = "### Found the config file." | timestamp
	Write-Verbose $msg
	$msg = "### Loading config file contents" | timestamp
	Write-Verbose $msg

	$global:qrcts = $qrCLIToolSettings
	return $qrCLIToolSettings

	} Catch {
		
		$msg = "### Config File missing. Execution Stopped" | timestamp
		Write-Host $msg

	}

# End function Load-qrCLIConfig
}

function Set-QRCreds {
<####

.SYNOPSIS
  Sets QRadar authentication information for future reference in other calls.
.DESCRIPTION
  Sets QRadar authentication information for future reference in other calls.
.PARAMETER username
    QRadar username
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development

.EXAMPLE
  Set-QRCreds michael.erana

####>

[CmdletBinding()]
param (
	[Parameter(Position=0)]
	[string]$username
    )
	
	filter timestamp {"$(Get-Date -Format G): $_"}
	$qrcts = $global:qrcts

	# Check to see if Setting have been loaded, load if not.
	if($qrcts.initSetDate.length -lt 1){
		$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
		Write-Verbose $msg
		$qrcts = Load-qrCLIConfig
	} Else {
		$msg = "Pulling settings from Global:qrcts" | timestamp
		Write-Verbose $msg
		$qrcts = $global:qrcts
		Write-Verbose $qrcts
	}

	# Use username from settings if not provided
	If ($username.length -lt 1){
		$msg = "No username provided. Using value $($qrcts.userName) from settings." | timestamp
		Write-Verbose $msg

		$username = $qrcts.userName.tolower()

		$msg = "Username set to:$userName from settings." | timestamp
		Write-Verbose $msg

	}

	$Credentials = Get-Credential -Credential (Get-Credential -UserName $username -Message "Login to QRadar")
	$RESTAPIUser = $Credentials.UserName
	$RESTAPIPassword = $Credentials.GetNetworkCredential().Password
	$apiCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($RESTAPIUser+":"+$RESTAPIPassword))
	$authCreds = "Basic $apiCreds"
	
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	$headers = @{}
	$headers.add("Version","12.0")
	$headers.add("Content-Type","application/JSON")
	$headers.add("Authorization", $authCreds)

	$global:headers = $headers

	$msg = "### QRadar Credentials set." | timestamp
	Write-Output $msg

}

function Find-QRAsset {
<#
.SYNOPSIS
  Finds QRadar Asset using an IP Address
.DESCRIPTION
  Finds QRadar Asset using an IP Address
.PARAMETER ipAddress
    IP Address to search for
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
.EXAMPLE
  Find-QRAsset 172.18.72.24

	  id hostName
    -- --------
		69065 Ares-iPhone.myco.local
		69141 TBILLI840.myco.local
		70357 STEG840G3.myco.local
		...
		...
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory=$true,
			   ValueFromPipelineByPropertyName=$true,
			   Position=0)]
		[string]$ipAddress
		)
	
	filter timestamp {"$(Get-Date -Format G): $_"}
	$qrcts = $global:qrcts

	# Check to see if Setting have been loaded, load if not.
	if($qrcts.initSetDate.length -lt 1){
		$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
		Write-Verbose $msg
		$qrcts = Load-qrCLIConfig
	} Else {
		$msg = "Pulling settings from Global:qrcts" | timestamp
		Write-Verbose $msg
		$qrcts = $global:qrcts
		Write-Verbose $qrcts
	}
	
	$headers = $global:headers
	$urlHost = $qrcts.qrcHost

	$fields = 'fields=id%2C%20hostnames%20(name),%20interfaces%20(%20ip_addresses%20(value,%20first_seen_profiler,%20last_seen_profiler)%20)'
	$filter = "filter=interfaces%20contains%20ip_addresses%20contains%20value%3D" + "'" + $ipAddress + "'"
	$ipSearchParams = $fields + "&" + $filter
	
	$url = "https://" + $urlHost + "/api/asset_model/assets?$ipSearchParams"
	Write-Verbose $msg
	$msg = "headers = $($headers.Authorization)" | timestamp
	Write-Verbose $msg
	$msg = "urlHost = $urlHost" | timestamp
	Write-Verbose $msg
	$msg = "url = $url" | timestamp

	$global:assetInfo = Invoke-RestMethod -Method GET -Headers $global:headers -Uri $url

	if ($assetInfo.count -gt 1){
		$msg = "!!! Found more than one Asset $($assetInfo.count) with that IP." | Timestamp
		write-verbose $msg
		
		$global:matchingQRAssetIds = New-Object System.Collections.ArrayList($null)
		foreach ($cAsset in $assetInfo){
			$asset = [pscustomobject][ordered]@{id = $cAsset.Id
				hostName = $cAsset.hostnames.name}
			[void]$global:matchingQRAssetIds.add($asset)
		}
		$matchingQRAssetIds
		return
	}

	if ($assetInfo.Count -lt 1){
	
		$msg = "!!! No assets found with IP Address: $ipAddress" | Timestamp
		write-verbose $msg
		return
	}

	$global:assetId = $assetInfo.id
	$global:assetInfo
}

function get-QRAssetInfo {
<#
.SYNOPSIS
  loads QRadar Asset info into a global variable
.DESCRIPTION
  loads QRadar Asset info into a global variable
.PARAMETER assetID
    Asset ID Number
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Era	na $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
.EXAMPLE
  get-qrassetinfo 177993

#>
[CmdletBinding()]
param (
	[Parameter(Mandatory=$true,
			   ValueFromPipelineByPropertyName=$true,
			   Position=0)]
	[int32]$assetId
    )

	filter timestamp {"$(Get-Date -Format G): $_"}
	$qrcts = $global:qrcts

	# Check to see if Setting have been loaded, load if not.
	if($qrcts.initSetDate.length -lt 1){
		$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
		Write-Verbose $msg
		$qrcts = Load-qrCLIConfig
	} Else {
		$msg = "Pulling settings from Global:qrcts" | timestamp
		Write-Verbose $msg
		$qrcts = $global:qrcts
		Write-Verbose $qrcts
	}

	$urlHost = $qrcts.qrcHost
	$headers = $global:headers
	$url = "https://" + $urlHost + "/api/asset_model/assets?filter=id%3D%22$assetId%22"
	$global:assetInfo = Invoke-RestMethod -Method GET -Headers $headers -Uri $url

	$global:assetId = $assetId
	$global:assetInfo
  }

function update-AssetProps {
<#
.SYNOPSIS
  Update QRadar asset properties using prepopulated array.
.DESCRIPTION
  Update QRadar asset properties using prepopulated array.
.PARAMETER assetID
    QRadar Asset ID
.PARAMETER newAssetProperties
    Dictionary list
.INPUTS
  newAssetProperties
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
  
.EXAMPLE

	$qrAssetPropValues = New-Object 'system.collections.generic.dictionary[string,string]'
	$qrAssetPropValues.add("newGivenName",$fqdn.split(".")[0])
	$qrAssetPropValues.add("newDescription",$newDescription)
	$qrAssetPropValues.add("busOwner",$busOwner)
	$qrAssetPropValues.add("busContact",$busContact)
	$qrAssetPropValues.add("techOwner","Department")
	$qrAssetPropValues.add("techContact",$techContact)
	$qrAssetPropValues.add("techUser",$techUser)
	$qrAssetPropValues.add("qraLocation","Physical location")
	$qrAssetPropValues

	Set-QRAssetProps $qrAssetPropValues

  update-AssetProps 69705 $newAssetProperties 
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory=$true,
	   ValueFromPipelineByPropertyName=$true,
	   Position=0)]
	[int32]$assetId,
	[Parameter(Mandatory=$true,
		Position=1)]$newAssetProperties
    )

	filter timestamp {"$(Get-Date -Format G): $_"}
	$qrcts = $global:qrcts

	# Check to see if Setting have been loaded, load if not.
	if($qrcts.initSetDate.length -lt 1){
		$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
		Write-Verbose $msg
		$qrcts = Load-qrCLIConfig
	} Else {
		$msg = "Pulling settings from Global:qrcts" | timestamp
		Write-Verbose $msg
		$qrcts = $global:qrcts
		Write-Verbose $qrcts
	}

	$urlHost = $qrcts.qrcHost
	$headers = $global:headers
	$url = "https://" + $urlHost + "/api/asset_model/assets?filter=id%3D%22$assetId%22"
	$assetInfo = Invoke-RestMethod -Method GET -Headers $headers -Uri $url

	$keyList = $newAssetProperties.keys
	$assetProps = New-Object System.Collections.ArrayList($null)

	foreach ($key in $keyList){

		[pscustomobject]$assetPropDetail = @{type_id = $key
			value = $newAssetProperties[$key]
			}
		write-verbose "### Adding`t$key`t-`t$($newAssetProperties[$key])" -verbose
		[void]$assetProps.add($assetPropDetail)

	}

	[pscustomobject]$propList = @{properties = $assetProps}

	$body = $propList | convertto-json -compress

	write-verbose "### Posting updated asset Properties`n" -verbose
	$url = "https://" + $urlHost + "/api/asset_model/assets/$assetId"
	Invoke-RestMethod -Method POST -Headers $headers  -body $body -Uri $url

	$url = "https://" + $urlHost + "/api/asset_model/assets?filter=id%3D%22$assetId%22"
	$global:assetInfo = Invoke-RestMethod -Method GET -Headers $headers -Uri $url
	# $assetInfo.properties | fl
	
}

function Set-QRAssetProps {
<#
.SYNOPSIS
  Loads Asset Properties into Dictionary list used for update-AssetProps.
.DESCRIPTION
	Loads Asset Properties into Dictionary list used for update-AssetProps. This is typically used with
	update QRadar asset properties. This is a usability middle step since the actual dictionary list that's
	used relies on cryptic codes for the various property values.
.PARAMETER qrAssetPropValues
    Dictionary List
.INPUTS
  qrAssetPropValues
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
  
.EXAMPLE

	$qrAssetPropValues = New-Object 'system.collections.generic.dictionary[string,string]'
	$qrAssetPropValues.add("newGivenName",$fqdn.split(".")[0])
	$qrAssetPropValues.add("newDescription",$newDescription)
	$qrAssetPropValues.add("busOwner",$busOwner)
	$qrAssetPropValues.add("busContact",$busContact)
	$qrAssetPropValues.add("techOwner","Department")
	$qrAssetPropValues.add("techContact",$techContact)
	$qrAssetPropValues.add("techUser",$techUser)
	$qrAssetPropValues.add("qraLocation","Physical location")
	$qrAssetPropValues

  Set-QRAssetProps $qrAssetPropValues
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory=$true,
			   ValueFromPipelineByPropertyName=$true,
			   Position=0)]
	$qrAssetPropValues
    )

	$newProps = New-Object 'system.collections.generic.dictionary[int32,string]'

	$newProps.add(1001,$qrAssetPropValues.newGivenName)
	$newProps.add(1004,$qrAssetPropValues.newDescription)
	$newProps.add(1005,$qrAssetPropValues.busOwner)
	$newProps.add(1006,$qrAssetPropValues.busContact)
	$newProps.add(1007,$qrAssetPropValues.techOwner)
	$newProps.add(1008,$qrAssetPropValues.techContact)
	$newProps.add(1009,$qrAssetPropValues.qraLocation)
	$newProps.add(1019,$qrAssetPropValues.techUser)
	
	If ($qrAssetPropValues.qrOSID){
		$newProps.add(1033,$qrAssetPropValues.qrOSID)
	}

	$global:newProps = $newProps

}

function Set-QRClipboard {
<#
.SYNOPSIS
  Loads windows clipboard with information
.DESCRIPTION
  Loads windows clipboard with information
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
  
.EXAMPLE
  Set-QRClipboard
#>
try {
		if ($global:fqdn.length -gt 1){
		$clipboardtext = "global:$assetId : $global:fqdn : $global:tgtIp"
		Set-Clipboard $global:assetId
		Start-Sleep -m 500
		Set-Clipboard $global:fqdn
		Start-Sleep -m 500
		Set-Clipboard $global:tgtIp
		Start-Sleep -m 500
		Set-Clipboard $clipboardtext
		Start-Sleep -m 500
		}
	} catch {
	$fqdn = $global:assetInfo.Properties.value[$assetInfo.Properties.type_id.indexOf(1002)]
	if ($global:fqdn.length -lt 1){
		$clipboardtext = "$global:assetId : hostName_here : $global:tgtIp"
		Set-Clipboard $global:assetId
		Start-Sleep -m 500
		Set-Clipboard $global:tgtIp
		Start-Sleep -m 500
		Set-Clipboard $clipboardtext
		Start-Sleep -m 500
		}
	}
}


function close-bulkQROffenses {
<#
.SYNOPSIS
  Closes specified Offenses
.DESCRIPTION
  Performs bulk QRadar Offense closes on Array of Offense IDs passed
.PARAMETER offenseList
    And array of OffenseIds to act upon
.PARAMETER cUser
    Username to assign to offense as it it closed.
.PARAMETER note
    Note text to add to offense
.PARAMETER meVerbose
    Boolean flag to enable verbose debugging output
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
.LINK
    Script posted over:
    http://sourceSite.local
.EXAMPLE
  ***ALERT***
  Before you use this function you MUST first run Set-QRCreds <<username>> to set credentials.
  First load all open offenses into an array list:
  
  $offenseList = New-Object System.Collections.ArrayList($null)

  $url = "https://<<QRadara Console Host>>/api/siem/offenses?filter=status%20%3D%20%22OPEN%22"
  [System.Collections.ArrayList]$offenseList = Invoke-RestMethod -Method GET -Headers $headers -Uri $url

  Next create another Array of just the offence Ids using a filter. Also set some variables to use for the other
  parameters.

  $gponOffenseList = $offenseList | Where {$_.description -like "*MALWARE-OTHER GPON exploit download attempt*"} | Select id
  $cUser="michael.erana"
  $noteText = "This offense was closed with reason: Non-Issue.`nExternal Compromised hosts probing network with source and dest inverted"

  Now we can use that new array to pass into the function.
    
  close-bulkQROffenses -oList $gponOffenseList -un $cUser -note $noteText
  
#>

[CmdletBinding()]
param (
	[Parameter(Mandatory=$true,
			   ValueFromPipelineByPropertyName=$true,
			   Position=0)]
		[System.Collections.ArrayList][alias('oList')]$offenseList,
		[string][alias('un')]$cUser = "michael.erana",
		[string][alias('note')]$noteText
    )

	filter timestamp {"$(Get-Date -Format G): $_"}
	$qrcts = $global:qrcts

	# Check to see if Setting have been loaded, load if not.
	if($qrcts.initSetDate.length -lt 1){
		$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
		Write-Verbose $msg
		$qrcts = Load-qrCLIConfig
	} Else {
		$msg = "Pulling settings from Global:qrcts" | timestamp
		Write-Verbose $msg
		$qrcts = $global:qrcts
		Write-Verbose $qrcts
	}

$urlHost = $qrcts.qrcHost
$totalOffenses = $offenseList.count
$headers = $global:headers
$i = 1
$cri = 1
$status="CLOSED"
$url = "https://" + $urlHost + "/api/siem/offenses"	
$IPv4RegexNew = '((?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d))'

	Foreach ($offenseId in $offenseList){

		$closeFilter = "$($offenseId.id)" + "?assigned_to=$cUser&closing_reason_id=$cri&status=$status"
		$closeURL = "$url/$closeFilter"
		$notesURL = "$url/$($offenseId.id)/notes?" + "note_text=$noteText"
		
		Write-Verbose $notesURL
		Write-Verbose $closeURL

		$offId = $offenseId.id
		$offSrc = $offenseId.offense_source
		$tgtIp = $offenseId.offense_source
		$offEvt = $offenseId.event_count
		$offFlow = $offenseId.flow_count

		if ([regex]::Matches($tgtIp, $IPv4RegexNew)){
			$geoURL = "https://" + $urlHost + "/api/services/geolocations?filter=ip_address%20%3D%20%22$tgtIp%22"
			$geoLocResult = Invoke-RestMethod -Method GET -Headers $headers -Uri $geoURL
		
			If ($geoLocResult.city.name.length -lt 1) {
				$geoCity = "[City Not Found]"
			} else {
				$geoCity = $geoLocResult.city.name
			}
			
			If ($geoLocResult.registered_country.name.length -lt 1) {
				$geoCountry = "[Country Not Found]"
			} else {
				$geoCountry = $geoLocResult.registered_country.name
			}
		} Else {
				$geoCity = "[City Not Found]"
				$geoCountry = "[Country Not Found]"
		}

		$offSrcGeo = "$geoCity, $geoCountry"

		# Only do Status if more than 10 offenses
		If ($totalOffenses -gt 10) {
			$ProgressArgs = @{
				Activity = "Bulk closing $totalOffenses offenses."
				Status = "Working on Offense # $offId ($offEvt / $offFlow) - $offSrc : $offSrcGeo"
				PercentComplete = (($i/$totalOffenses)*100)
				CurrentOperation = "$i of $totalOffenses"
			}

			# Write-Host "### Working on Offense # $offId ($offEvt / $offFlow) - $offSrc : $offSrcGeo"
			Write-Progress @ProgressArgs
			$i++
		}

		$offenseNotePost = Invoke-RestMethod -Method POST -Headers $headers -Uri $notesURL
		$offenseClose = Invoke-RestMethod -Method POST -Headers $headers -Uri $closeURL
		
	}

	Write-Progress -Activity "### $totalOffenses Offenses closed." -Completed 

}

function Load-QRNets {
<#
.SYNOPSIS
  Loads QRadar Network Lists
.DESCRIPTION
  Loads QRadar Network Lists
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
.LINK
    Script posted over:
    http://sourceSite.local
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>

filter timestamp {"$(Get-Date -Format G): $_"}
$qrcts = $global:qrcts

# Check to see if Setting have been loaded, load if not.
if($qrcts.initSetDate.length -lt 1){
	$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
	Write-Verbose $msg
	$qrcts = Load-qrCLIConfig
	} Else {
	$msg = "Pulling settings from Global:qrcts" | timestamp
	Write-Verbose $msg
	$qrcts = $global:qrcts
	Write-Verbose $qrcts
	}

$urlHost = $qrcts.qrcHost
$headers = $global:headers
$IPv4Regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
$cidrIPv4Regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
$cidrRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$"
$allNets = New-Object System.Collections.ArrayList

$url = "https://" + $urlHost + "/api/config/network_hierarchy/networks"
$netList = Invoke-RestMethod -Method GET -Headers $headers -Uri $url

$url = "https://" + $urlHost + "/api/config/network_hierarchy/staged_networks"
$stNetList = Invoke-RestMethod -Method GET -Headers $headers -Uri $url

$invalidNets = ($netList | Where {$_.description -like "Default Network"}).id

### Consolidate networks into $cleanNets

foreach ($net in $netList) {

	If (-NOT ($invalidNets -contains $net.id) ) {
		[void]$allNets.add($net)
		}

	}
foreach ($net in $stNetList) {

	If (-NOT ($invalidNets -contains $net.id) ) {
		[void]$allNets.add($net)
		}

	}

$cleanNets = $allNets | Select Id,Name,Cidr,Description,Country_Code -Unique | Sort Cidr
remove-variable netList, stNetList, allNets

$fullNetList = New-Object System.Collections.ArrayList($null)
foreach ($net in $cleanNets) {

	$netIp,$subnetMask = ConvertFrom-cidrToIpv4Mask $net.cidr | Out-Null

	$net.cidr -match $cidrRegex
	$cidr = $matches[5]
	$net.cidr -match $cidrIPv4Regex
	$IPAddress = $matches[0]
	$ipaddr = [Net.IPAddress]::Parse($IPAddress)
	$maskaddr = [Net.IPAddress]::Parse((ConvertFrom-Int64ToIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2))))
	$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)
	$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))
	[Int64]$startaddr = ConvertFrom-IPToInt64 -ip $networkaddr.ipaddresstostring 
	[Int64]$endaddr = ConvertFrom-IPToInt64 -ip $broadcastaddr.ipaddresstostring 

	$udNet = [pscustomobject][ordered]@{
		Id = $net.ID
		Name = $net.Name
		Cidr = $net.cidr
		netIp = $ipaddr.IPAddressToString
		mask = $maskAddr.IPAddressToString
		startI64 = $startaddr
		endI64 = $endaddr
		Description = $net.Description
		Country_Code = $net.Country_Code
	}

	[void]$fullNetList.add($udNet)

	}

	Return $Local:fullNetList

}

function Get-QRWhoIs {
<#
.SYNOPSIS
  Retrieves WHOIS Information from QRadar
.DESCRIPTION
  Uses QRadar WHOIS utility to retrieve information
.PARAMETER ip
    IP Address to retrieve WHOIS information for.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
.LINK
    Script posted over:
    http://sourceSite.local
.EXAMPLE
  Get-QRWhois 13.86.101.172
  
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory=$false,Position=0,ValueFromPipeline)]
		[string]$ip
)

	filter timestamp {"$(Get-Date -Format G): $_"}
	$qrcts = $global:qrcts

	# Check to see if Setting have been loaded, load if not.
	if($qrcts.initSetDate.length -lt 1){
		$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
		Write-Verbose $msg
		$qrcts = Load-qrCLIConfig
	} Else {
		$msg = "Pulling settings from Global:qrcts" | timestamp
		Write-Verbose $msg
		$qrcts = $global:qrcts
		Write-Verbose $qrcts
	}

setCwd
$cwd = $global:cwd
$urlHost = $qrcts.qrcHost

$url = "https://" + $urlHost + "/api/services/whois_lookups?IP=$ip"
$whoisJob = Invoke-RestMethod -Method Post -Headers $headers -Uri $url

$url = "https://" + $urlHost + "/api/services/whois_lookups/" + $whoisJob.Id
$global:whoisResult = Invoke-RestMethod -Method GET -Headers $headers -Uri $url

While ($whoisResult.status -eq "PROCESSING"){
	Write-Host "### Looking for $ip - Waiting 2s for results..."
	start-sleep 2
	$global:whoisResult = Invoke-RestMethod -Method GET -Headers $headers -Uri $url
}

[System.Collections.ArrayList]$whoisMessage = $whoisResult.message.replace('","','"~"').split("~").replace('"',"")

$global:whoismessage = $whoisMessage

# $whoisMessage[10..32]

Try {
	$startNet,$endNet = ($whoismessage -imatch "inetnum:" | Select -first 1).split(" ") -match "[\d{1-3}]\.*"
}	catch {
	$startNet,$endNet = ($whoismessage -imatch "NetRange:" | Select -first 1).split(" ") -match "[\d{1-3}]\.*"
}

$whoisInfo = [pscustomobject][ordered]@{
	ip = $ip
	startNet = $startNet
	endNet = $endNet
	NetName = [regex]::match($whoisMessage,"netname:\s+([\w\.\-]*)",@('Ignorecase')).groups[1].value
	CIDR = [regex]::match($whoisMessage,"CIDR:\s+([\w\.\-\/\,\s]*)\s",@('Ignorecase')).groups[1].value
	route = [regex]::match($whoisMessage,"route:\s+([\w\.\-\/\,\s]*)\s",@('Ignorecase')).groups[1].value
	Descr = [regex]::match($whoisMessage,"Descr:\s+([\w\.\-\/\,\s]*)\s",@('Ignorecase')).groups[1].value
	Org = [regex]::match($whoisMessage,"organization:\s+([\w\.\-\s\(\)]+)\s",@('Ignorecase')).groups[1].value
	Country = [regex]::match($whoisMessage,"country:\s+([\w\.\-\s]*)\s",@('Ignorecase')).groups[1].value
	City = [regex]::match($whoisMessage,"city:\s+([\w\.\-\s]*)\s",@('Ignorecase')).groups[1].value
	Src = [regex]::match($whoisMessage,"source:\s+([\w\.\-]*)",@('Ignorecase')).groups[1].value
}
# Write-Verbose "Start:`t`t$startNet`nEnd:`t`t$endNet`ninetneum:`t$inetnum`nNetName:`t$wiNetName`nCIDR:`t`t$wiCIDR`nOrganization:`t$wiOrg`nDescription:`t$wiDescr`nCity:`t`t$wiCity`nCountry:`t$wiCountry`nSource:`t$wiSrc" -verbose:$True
# Write-Verbose $($whoisInfo) -verbose:$True

return $whoisInfo

}


function Get-QROffenses{
<#
.SYNOPSIS
  Retrieves all Open Offenses in QRadar
.DESCRIPTION
	Retrieves all Open Offenses in QRadar and loads into a global session variable: offenseList
	The contents of the variable are used for CLI Offense closing.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 174 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-04-13 10:08:21 -0400 (Mon, 13 Apr 2020) $
  Purpose/Change: Initial script development
.LINK
    Script posted over:
    http://sourceSite.local
.EXAMPLE
	Get-QROffenses
  
#>

	setCwd
	$cwd = $global:cwd
	
	filter timestamp {"$(Get-Date -Format G): $_"}
	$qrcts = $global:qrcts

	# Check to see if Setting have been loaded, load if not.
	if($qrcts.initSetDate.length -lt 1){
		$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
		Write-Verbose $msg
		$qrcts = Load-qrCLIConfig
	} Else {
		$msg = "Pulling settings from Global:qrcts" | timestamp
		Write-Verbose $msg
		$qrcts = $global:qrcts
		Write-Verbose $qrcts
	}

	$urlHost = $qrcts.qrcHost

	Write-Output "### Fetching current Offenses from QRadar. Be patient..." | timestamp
	$global:offenseList = New-Object System.Collections.ArrayList($null)
	$url = "https://" + $urlHost + "/api/siem/offenses?filter=status%20%3D%20%22OPEN%22"
	[System.Collections.ArrayList]$global:offenseList = Invoke-RestMethod -Method GET -Headers $global:headers -Uri $url
	$msg = "Current Offense Count:`t $($global:offenseList.count)" | timestamp
	$msg = "$msg`n" + $("Results stored in offenseList" | timestamp)
	Write-Output $msg

}

function Get-QRAQL {
<#
.SYNOPSIS
  Retrieves AQL Results from QRadar Console
.DESCRIPTION
  Uses provided AQL to retrieve results from QRadar
.PARAMETER aql
    AQL Searcch to retrieve.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev: 164 $
  Author:         $Author: Michael.Erana $
  Creation Date:  $Date: 2020-03-13 10:58:16 -0400 (Fri, 13 Mar 2020) $
  Purpose/Change: Initial script development
.LINK
    Script posted over:
    http://sourceSite.local
.EXAMPLE

	$ampFocusedAQL = '
	select QIDNAME(qid) as ''EventName'',
		sum("eventCount") as ''EventCount'',
		UniqueCount(category) as ''ucLLCategory'',
		UniqueCount("Hostname") as ''ucHostname'',
		UniqueCount("ampDetection") as ''ucDetection'',
		UniqueCount("ampDisposition") as ''ucDisposition''
	from events 
	where logSourceId=''1664''
		and "ampEventType" ILIKE ''Cloud IOC''
		or "ampEventType" ILIKE ''System Process Protected''
		or "ampEventType" ILIKE ''Threat Detected''
		or "ampEventType" ILIKE ''Quarantine Failure''
		or "ampEventType" ILIKE ''Scan Completed With Detections''
		or "ampEventType" ILIKE ''Executed malware''
		or "ampEventType" ILIKE ''Unknown Cisco AMP Event''
		or "ampEventType" ILIKE ''Malicious Activity Protection''
		or "ampEventType" ILIKE ''Generic IOC''
	Group By "EventName"
	Start ''startDateTime''
	Stop ''stopDateTime''
	'
	$startDateTime = '2020-04-27 00:00'
	$stopDateTime = '2020-04-28 00:00'

	$aql = $ampFocusedAQL
	$aql = $aql.replace("startDateTime",$startDateTime)
	$aql = $aql.replace("stopDateTime",$stopDateTime)

	$search = Get-QRAQL $aql
  
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory=$True,Position=0,ValueFromPipeline)]
		[string]$aql
	)

	filter timestamp {"$(Get-Date -Format G): $_"}
	$qrcts = $global:qrcts

	# Check to see if Setting have been loaded, load if not.
	if($qrcts.initSetDate.length -lt 1){
		$msg = "Config not loaded. Running Load-qrCLIConfig" | timestamp
		Write-Verbose $msg
		$qrcts = Load-qrCLIConfig
	} Else {
		$msg = "Pulling settings from Global:qrcts" | timestamp
		Write-Verbose $msg
		$qrcts = $global:qrcts
		Write-Verbose $qrcts
	}

	$urlHost = $qrcts.qrcHost

	$searchBaseURL="https://" + $urlHost + "/api/ariel/searches?query_expression="
	$searchURL = $searchBaseURL + [System.Web.HttpUtility]::UrlEncode($aql)

	$searchRun = Invoke-RestMethod -Method Post -Headers $headers -Uri $searchURL

	$searchURL = "https://" + $urlHost + "/api/ariel/searches/$($searchRun.search_id)"
	$searchDone = (Invoke-RestMethod -Method Ge$headerst -Headers $headers -Uri $searchURL).Completed

	While ($searchDone -ne "True"){

		$msg = "zzz Results for search not ready. Snoozing for 5s." | Timestamp
		Write-Verbose $msg 
		Start-Sleep 5s
		$searchDone = (Invoke-RestMethod -Method Get -Headers $headers -Uri $searchURL).Completed

	}

	$searchResult = New-Object System.Collections.ArrayList($null)

	$searchURL = "https://" + $urlHost + "/api/ariel/searches/$($searchRun.search_id)/results" 
	[System.Collections.ArrayList]$searchResult = [pscustomobject](Invoke-RestMethod -Method Get -Headers $headers -Uri $searchURL).Events

return $searchResult

}
function Load-wClipboard {

[CmdletBinding()]
param (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [array]$resultArray
    )

	Set-Clipboard $resultArray.intIp
	Start-Sleep -m 500
	Set-Clipboard $resultArray.extIp
	Start-Sleep -m 500
	Set-Clipboard $resultArray.DNS

}

Export-ModuleMember -Function * -Alias *




