# About qrcli
This is a Powershell Module to facilitate QRadar access via API.

# Installation

Simply copy the Module directory to your powershell module location. To detemine your powershell module paths you can do the following:

PS C:\WIP> $(gci env:PSModulePath).value.split(";")

C:\Users\me-g33k.yourco\Documents\PowerShell\Modules

C:\Program Files\PowerShell\Modules

c:\program files\powershell\7\Modules

C:\Windows\system32\WindowsPowerShell\v1.0\Modules

C:\Program Files\WindowsPowerShell\Modules

C:\Windows\system32\WindowsPowerShell\v1.0\Modules

C:\Users\me-g33k.yourco\Documents\WindowsPowerShell\Scripts


After you've copied the folder to the PSModuleDirectory, simply import the module into the powershell session.

There is a config file that is useful as well open up createSettings.ps1 and edit the variables set as appropriate specifically the qrcHost value. The Username and cwd variables can also be set as appropriate if they do not match what is required.



# NOTE

There are a lot of variables that are kept active in the session. I would recommend NOT letting the powershell session persist over long periods of un-attended time.

# Functions List
  close-bulkQROffenses
  
  Find-QRAsset
  
  Get-QRAssetInfo
  
  Get-QRAQL
  
  Get-QRWhois
  
  Load-QRNets
  
  Set-QRCreds
  
  Update-AssetProps

## function Set-QRCreds
.SYNOPSIS

  Sets QRadar authentication information for future reference in other calls.
  
.DESCRIPTION

  Sets QRadar authentication information for future reference in other calls.
  
.EXAMPLE

  Set-QRCreds michael.erana
