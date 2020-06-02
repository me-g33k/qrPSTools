filter timestamp {"$(Get-Date -Format G): $_"}

$userSettings = [ordered]@{
	initSetDate = get-date -format "yyyy-MM-dd hh:mm"
	userName = $env:USERNAME
	cwd = $env:temp
	qrcHost = "console.yourco.com"
}

$userSettings | Convertto-JSON | Out-File $psscriptroot\qrCLITools_settings.json


