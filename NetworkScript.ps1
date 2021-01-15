function Get-RemoteIPDetails {

$runCounter = 0
$spsServerNC = 'sxwnsps001'
$cred = ''
$SiteCode = Read-Host -Prompt 'Enter 3-letter Site Code'
$RemoteServerName=$SiteCode+$spsServerNC
Write-Output 'Getting IP Configuration for ' $RemoteServerName
$NetworkAdapterConfig = Invoke-Command -ComputerName $RemoteServerName -Credential $cred -ScriptBlock { Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration }
foreach ($NetworkAdapter in $NetworkAdapterConfig) {
    if ($NetworkAdapter.IPAddress -eq $null) {$nodata ='No Details to show'}
    else {$IPDetails = $NetworkAdapter | Select-Object Index,@{n='SiteCode';e={$SiteCode}}, DNSHostName, @{n='IPAddress';e={$psitem.IPAddress}},@{n='SubnetMask';e={$PSItem.IPSubnet}},
                                           @{n='GTW';e={$PSItem.DefaultIPGateway}},@{n='DNSServer';e={$PSItem.DNSServerSearchOrder}}, 
                                           @{n='WINSServer';e={$psitem.WINSPrimaryServer}},@{n='MAC';e={$psitem.MACAddress}} | Export-Csv C:\script_output\final.csv -Append
                                           $runCounter++
                                           $IPDetails
        }
        }
if ($runCounter -gt 0) {Write-Host 'Corpnet Details Added to site list'}
else {'No IP details found'}

}


function Get-RemoteIPDetails222{

     [CmdletBinding()] 
     Param 
        (

        [Parameter(Mandatory=$false,Position=1)]
        [String] $hostName
        )


$username = “”
$password = “”
$credentials =  $username,$password
$runCounter = 0
$spsServerNC = ''
$cred = ''
$SiteCode = Read-Host -Prompt 'Enter Site Code'
$RemoteServerName=$SiteCode+$spsServerNC
Write-Output 'Getting IP Configuration for ' $RemoteServerName
$NetworkAdapterConfig = Invoke-Command -ComputerName $RemoteServerName -Credential $credentials -ScriptBlock { Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration }
foreach ($NetworkAdapter in $NetworkAdapterConfig) {
    if ($NetworkAdapter.IPAddress -eq $null) {$nodata ='No Details to show'}
    else {$IPDetails = $NetworkAdapter | Select-Object Index,@{n='SiteCode';e={$SiteCode}}, DNSHostName, @{n='IPAddress';e={$psitem.IPAddress}},@{n='SubnetMask';e={$PSItem.IPSubnet}},
                                           @{n='GTW';e={$PSItem.DefaultIPGateway}},@{n='DNSServer';e={$PSItem.DNSServerSearchOrder}}, 
                                           @{n='WINSServer';e={$psitem.WINSPrimaryServer}},@{n='MAC';e={$psitem.MACAddress}} | Export-Csv C:\script_output\final.csv -Append
                                           $runCounter++
                                           
        }
        }
if ($runCounter -gt 0) {Write-Host 'Corpnet Details Added to site list'

Write-Host $IPDetails

}

else {'No IP details found'}

}

function set-set {


}


$cred=Get-Credential
$sess = New-PSSession -Credential $cred -ComputerName uk1sxwn00698
Enter-PSSession $sess
<Run commands in remote session>
Exit-PSSession
Remove-PSSession $sess
Get-Content [txt file]