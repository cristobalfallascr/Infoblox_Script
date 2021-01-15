# Get-ADReplicationSubnet -Filter "Site -eq ''" | select Name, Location
# Get-ADReplicationSubnet -Identity "10.102.80.0/24" -Properties *
# Get-ADReplicationSubnet -Filter "Site -eq ''" | select Name, Location


# $subnetInAD = "172.25.69.96/29"
# $mySearch = Get-ADReplicationSubnet -Identity $subnetInAD -Properties *
# $adCode = "'"+$mySearch.Site.Substring(3,5)+"'"
# Get-ADReplicationSubnet -Filter "Site -eq $adCode" | select Name, Location

# Write-Host $mySearch.Site.Substring(3,5),  $mySearch.Location, $mySearch.name
# write-Host 


function Get-SubnetInAD {

[CmdletBinding()] 
 Param 
    
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $IPAddress,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $Netmask
    )

    $argumentList = "-IPAddress $IPAddress -NetMask $Netmask"
    $ipCalc = "C:\Test_Scripts\ipcalc.ps1"
	$getSubnetInfo = Invoke-Expression "$ipCalc $argumentList"
    $subnetID = $getSubnetInfo.Network
    $hostMinimum = $getSubnetInfo.HostMin
    Write-Host "Subnet range for this IP is " $subnetID
       
   
   try {
   $mySearch = Get-ADReplicationSubnet -Identity $subnetID -Properties *
   
    $adCode = "'"+$mySearch.Site.Substring(3,5)+"'"

    Write-Host "Subnet found: " $mySearch.Site.Substring(3,5),  $mySearch.Location, $mySearch.name -ForegroundColor Green
    }
    Catch{ $notFound = $Error
    Write-Host "Not in AD" -ForegroundColor Red
    #Write-Host "Other subnets: "
    #Get-ADReplicationSubnet -Filter "Site -eq $adCode" | select Name, Location
    }
    Finally{}


    Write-Host "=============="
    

    
    
}


