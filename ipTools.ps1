using namespace System.Net
function ConvertFrom-IPToInt64 () {
<#
.SYNOPSIS
  Converts given IP Address to an Int64 value
.DESCRIPTION
  Converts given IP Address to an Int64 value
.PARAMETER ip
    An IPV4 address
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        $Rev$
  Author:         $Author$
  Creation Date:  $Date$
  Purpose/Change: Initial script development
.LINK
    Script posted at reddit by /u/Ta11ow:
    https://www.reddit.com/r/PowerShell/comments/8u14wl/check_a_list_of_ips_against_a_list_of_subnets/
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)]
		[string]
		$ip
	) 

	PROCESS {
		$octets = $ip.split(".") 
		[int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
	}
} 

function ConvertFrom-Int64ToIP() { 
<#
.SYNOPSIS
  Converts an Int64 value to an IPV4 address
.DESCRIPTION
  Converts an Int64 value to an IPV4 address
.PARAMETER int
    Int64 value to convert to IPV4 address
.INPUTS
  none
.OUTPUTS
  none
.NOTES
  Version:        $Rev$
  Author:         $Author$
  Creation Date:  $Date$
  Purpose/Change: Initial script development
.LINK
    Script posted at reddit by /u/Ta11ow:
    https://www.reddit.com/r/PowerShell/comments/8u14wl/check_a_list_of_ips_against_a_list_of_subnets/
.EXAMPLE
  <Example goes here. Repeat this attribute for more than one example>
#>
  [CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)]
		[int64]
		$int
	) 
	PROCESS {
		(([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
		# ([ipaddress]$int).IPAddressToString
	}
}

Function Get-IPsInRange {
<#
.SYNOPSIS
  <Overview of script>
.DESCRIPTION
  <Brief description of script>
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.INPUTS
  <Inputs if any, otherwise state None>
.OUTPUTS
  <Outputs if any, otherwise state None - example: Log file stored in C:\Windows\Temp\<name>.log>
.NOTES
  Version:        $Rev$
  Author:         $Author$
  Creation Date:  $Date$
  Purpose/Change: Initial script development
.LINK
    Script posted at reddit by /u/Ta11ow:
    https://www.reddit.com/r/PowerShell/comments/8u14wl/check_a_list_of_ips_against_a_list_of_subnets/
.EXAMPLE
	Get-IPsInRange -IPAddress 192.168.1.0/24
	Get-IPsInRange -IPAddress 192.168.1.0 -mask 255.255.255.0
	Get-IPsInRange -Start 192.168.1.10 -End 192.168.1.55
#>
	[CmdletBinding(DefaultParameterSetName="IPAddress")]
	PARAM (
		[Parameter(ParameterSetName="IPAddress",Mandatory=$True)]
		[string]
		$IPAddress,
		
		[Parameter(ParameterSetName="IPAddress",Mandatory=$False)]
		[string]
		$Mask,
		
		[Parameter(ParameterSetName="StartEnd",Mandatory=$True)]
		[string]
		$Start,
		
		[Parameter(ParameterSetName="StartEnd",Mandatory=$True)]
		[string]
		$End
	)
	
	BEGIN {
		# Pure IPv4 Address
		$IPv4Regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
		$cidrIPv4Regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
		$cidrRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$"
		$RangeRegex = "({0})-({1})" -f $IPv4Regex.Replace('$',''), $IPv4Regex.Replace('^','')
		if ($IPAddress -match $IPv4Regex) {
			# IP is Fine as is
		}
		elseif ($IPAddress -match $cidrRegex) {
			# IP Address with CIDR block
			$cidr = $matches[5]
			Write-Host "Cidr is $cidr"
			$temp = $IPAddress -match $cidrIPv4Regex
			$IPAddress = $matches[0]
			Write-Host "First IP is $IPAddress"
		}
		elseif ($IPAddress -match $RangeRegex) {
			$startaddr = ConvertFrom-IPToInt64 -ip $matches[1]
			$endaddr = ConvertFrom-IPToInt64 -ip $matches[5]
		}
	}
	
	PROCESS {
		if ( [string]::IsNullOrEmpty($startaddr) -or [string]::IsNullOrEmpty($endaddr) ) {
			if ($PSBoundParameters.ContainsKey("IPAddress")) {
				$ipaddr = [Net.IPAddress]::Parse($IPAddress)
			} 
			
			if ($PSBoundParameters.ContainsKey("mask")) {
				$maskaddr = [Net.IPAddress]::Parse($mask)
			} 
			elseif (-Not([string]::IsNullOrEmpty($CIDR))) {
				$maskaddr = [Net.IPAddress]::Parse((ConvertFrom-Int64ToIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2))))
			}
			else {
				$mask = "255.255.255.255"
				$maskaddr = [Net.IPAddress]::Parse($mask)
			}
			
			if ($PSBoundParameters.ContainsKey("IPAddress")) {
				$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)
			} 
			
			if ($PSBoundParameters.ContainsKey("IPAddress")) {
				$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))
			} 
			 
			if ($PSBoundParameters.ContainsKey("IPAddress")) { 
				$startaddr = ConvertFrom-IPToInt64 -ip $networkaddr.ipaddresstostring 
				$endaddr = ConvertFrom-IPToInt64 -ip $broadcastaddr.ipaddresstostring 
			} else { 
				$startaddr = ConvertFrom-IPToInt64 -ip $start 
				$endaddr = ConvertFrom-IPToInt64 -ip $end 
			}
		}
		else {
			
		}
		 
		for ($i = $startaddr; $i -le $endaddr; $i++) { 
			ConvertFrom-Int64ToIP -int $i 
		}
	}
}

function Test-IPInSubnet {

    [CmdletBinding()]
    param(
        [Parameter(
            Position = 0, 
            Mandatory, 
            ValueFromPipelineByPropertyName
        )]
        [ValidateNotNull()]
        [IPAddress]
        $Subnet = "172.20.76.0",

        [Parameter(
            Position = 1, 
            Mandatory, 
            ValueFromPipelineByPropertyName
        )]
        [Alias('Mask')]
        [ValidateNotNull()]
        [IPAddress]
        $SubnetMask = "255.255.254.0",

        [Parameter(
            Position = 0, 
            Mandatory, 
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [Alias('Address')]
        [ValidateNotNull()]
        [IPAddress]
        $IPAddress = "172.20.76.5"
    )
    process {
        $Subnet.Address -eq ($IPAddress.Address -band $SubnetMask.Address)
    }
}

function ConvertFrom-cidrToIpv4Mask {

[CmdletBinding()]
param(
	[Parameter(Mandatory=$True)]
	[string]
	$IPAddress,
	[boolean]$meDebug)

$IPv4Regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
$cidrIPv4Regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
$cidrRegex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$"

if ($IPAddress -match $cidrRegex) {
		# IP Address with CIDR block
		$cidr = $matches[5]
		# Write-Verbose "Cidr is $cidr" -verbose:$meDebug
		$temp = $IPAddress -match $cidrIPv4Regex
		$IPAddress = $matches[0]
		# Write-Verbose "First IP is $IPAddress" -verbose:$meDebug
		$subnetMask = ('{0:X}'-f(-1-shl32-$cidr)-split'(..)'|?{$_}|%{0+('0x'+$_)})-join'.'
	}

return $ipAddress,$subnetMask
}
