

 ##Custom Functions

#Login and establishes session to the Infobloc Web API

function Set-IBSessionDEV {
    Set-IBConfig -ProfileName 'mygrid' -WAPIHost '[]' -WAPIVersion 'latest' `
    -Credential (Get-Credential) -SkipCertificateCheck
    }

# Get Subnet information from IP address and Mask obtained from VC or provided by customer

function Get-SubnetID {
[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $IPAddress,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $Netmask
    )

    $argumentList = "-IPAddress $IPAddress -NetMask $Netmask"
    $ipCalc = "E:\HDPTools\InfoBlox_Automation\ipcalc.ps1"
	$getSubnetInfo = Invoke-Expression "$ipCalc $argumentList"
    $subnetID = $getSubnetInfo.Network
    Write-Host "Subnet range for this IP is " $subnetID
    Return $subnetID |Out-Null
    }

#Check if Subnet exits on infoblox, only for confirmation purpose

function Check-IBSubnetRange {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $SubnetID
    )

    $subnetIB = Get-IBObject -ObjectType 'network' -Filters "ipv4addr=$SubnetID" 
        if ($subnetIB -ne $null){
            Write-Output "Subnet found on Infoblox Database:   " $subnetIB.network | Write-Host }
        else{Write-Output "Subnet not found on infoblox Database." |Write-Host
        Break }
        Write-Host $subnetIB
        return($subnetIB) | Out-Null
}

# Get Next available IP, verify if responds to ping

function Get-NextAvailableIP {
    
    [CmdletBinding()] 
     Param 
        (
        [Parameter(Mandatory=$true,Position=0)]
        [String] $subnetID,
        [Parameter(Mandatory=$false,Position=1)]
        [int] $requiredIPs =1
        )

#Check if Subnet exits in IB data base, Subnet information is saved to $subnetIB

. Check-IBSubnetRange -SubnetID $subnetID | Write-Output
  [System.Collections.ArrayList]$resposiveIPs = @()
  [System.Collections.ArrayList]$availableIPs = @()
  $resposiveIPs.Clear()
  $availableIPs.Clear()

  #Reserve the first three IPs from every subnet
                
  $callAllIPs = Get-IBObject -type ipv4address -filters "network=$subnetID"
  [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
  Write-Output 'IP Address below will not be assigned:' $reservedNDIPs 
    
 if ($subnetIB -ne $null){
                Do{
                    $nextAvailIP = $subnetIB| Invoke-IBFunction -name 'next_available_ip' -args @{num=$requiredIPs;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                    #Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                    foreach ($ipAddress in $nextAvailIP ) {
                        Write-Output "Testing availability of $ipAddress" | Write-Host
                        $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                            If($pingTest -eq $true){
                                Write-Output "IP Address is in use"
                                $ipInUse =$ipAddress
                                $resposiveIPs.Add($ipInUse) |Out-Null
                                 Write-Host "IP Address is in use" -ForegroundColor Red
                                } else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                $ipNotInUse=$ipAddress
                                $availableIPs.Add($ipNotInUse) |Out-Null
                                        }
                       
                     } 
            	} Until ($pingTest -eq $false)
                
            Write-Host "IPs Below are avaible" $availableIPs
                
            
            
            } else{Write-Output "No IPs to display" |Write-Host}


}

# Assign next Available IP in Infoblox on given subnet

function New-SingleHostRecord{
    [CmdletBinding()] 
    Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $HostName,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $Zone,
    [Parameter(Mandatory=$true,Position=2)]
    [String] $subnetID
    )

    if($zone -eq 'corpnet1d.com')
            {$zone='.corpnet1d.com'}
    elseif($zone -eq 'corpnet2d.com')
            {$zone='.corpnet2d.com'}
    else
            {Write-Output "Invalid Zone selected."
             Break}

   
   . Get-NextAvailableIP -subnetID $subnetID

   if($nextAvailIP -ne $null){
   
        ##Set new IBrecord
    

        try{
            Write-Output 'Setting up Host DNS entry' | Write-Host
            $hostFQDN = $hostName + $zone
        	$newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
            $newHost | New-IBObject -type record:host
            ##Update extra Attributes

            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN"
            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host') 
            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}}
            $updateHost | Add-Member @{comment='Record created by HD&P script'}
            $updateHost | Set-IBObject
            Write-Host 'DNS Record / IP allocation completed - ' $hostFQDN ' with IPAddress: ' $nextAvailIP -ForegroundColor Green

        }

        Catch{
        Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
        Break        
        }
        Finally{}
   


    }
   
    else{ 
        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
        }
   
    }
    
# Create a host reservation using next available IP on given subnet

function New-IPReservation{
    [CmdletBinding()] 
    Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $HostName,
    [Parameter(Mandatory=$false,Position=1)]
    [String] $Zone,
    [Parameter(Mandatory=$true,Position=2)]
    [String] $subnetID
    )

    if($zone -eq 'corpnet1d.com')
            {$zone='.corpnet1d.com'}
    elseif($zone -eq 'corpnet2d.com')
            {$zone='.corpnet2d.com'}
    else
            {Write-Output "Invalid Zone selected."
             Break}

 
   . Get-NextAvailableIP -subnetID $subnetID

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                       try{
                            
                            Write-Output "Setting up Reservation ' $nextAvailIP for $HostName"| Write-Host
                            New-IBObject -type fixedaddress -IBObject @{ipv4addr=$nextAvailIP;mac='00:00:00:00:00:00';name=$hostName}
                            Write-Host 'Reserverd successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
   
    }  

# Creates DNS records using list from CSV. IPs are predefined on the csv file

function Set-IPsfromCSV {

[CmdletBinding()] 
Param 
(
[Parameter(Mandatory=$true,Position=0)]
 [String] $filePath)


$hostList =@{}
[System.Collections.ArrayList]$resposiveIPs =@()
[System.Collections.ArrayList]$availableIPs=@()
[System.Collections.ArrayList]$inUseIPs =@()
$verifiedhostList =@{}
$counter=0

$hostList = Import-Csv -Path $filePath

Write-Host "The following list of hos will be added:" 
Write-Output $hostList | Format-Table
Write-Host "Obtaining Network/SubnetID"

. Get-SubnetID -IPAddress $hostList.IPAddress[0] -Netmask $hostList.Netmask[0]

Write-Host "Allocating" $hostList.IPAddress.Count  "records in total."

Write-Host "Checking Subnet exist on IB"

. Check-IBSubnetRange -SubnetID $subnetID

#Get all Objects in given subnet, set an array with IPs which already have a record in Infoblox

$callSubnetObj = Get-IBObject -type ipv4address -filters "network=$subnetID"

foreach($ip in $callSubnetObj){
    if( $ip.status -eq 'USED'){
            $inUseIPs.add($ip.ip_address) | out-null
      }
}
Write-Host "IPs in use: " $inUseIPs



        foreach ($ipAddress in $hostList.IPAddress ) {
                    
            Write-Output "Testing availability and status of $ipAddress" | Write-Host
            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                If($pingTest -eq $true){
                    $ipInUse =$ipAddress
                    $resposiveIPs.Add($ipInUse) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    }

                elseif($ipAddress -iin $inUseIPs){
                     Write-Host "There a record for this IP, skipping this entry"-ForegroundColor Red
                    }
                        
                else { 
                     Write-Host "IP address is available, no ping, no record!" -ForegroundColor Green | Write-Output
                     $ipNotInUse=$ipAddress
      
                            ##Set new IBrecord
    
                                try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Output "Setting up Host DNS entry with ' $ipNotInUse for $hostFQDN"| Write-Host
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ipNotInUse } ) }
                                $newHost | New-IBObject -type record:host

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}
                                $updateHost | Set-IBObject 
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                                                 
                            }
                        Finally{}
   
                    }
        $counter++
        }
}

#Checks the 3 subnets provided for Nutanix exist on Infoblox

function Check-IBNutanixRanges {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $ILOSubnetID,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $NTXSubnetID,
    [Parameter(Mandatory=$true,Position=2)]
    [String] $VMOTSubnetID,
    [Parameter(Mandatory=$true,Position=3)]
    [String] $siteCode,
    [Parameter(Mandatory=$False,Position=4)]
    [String] $zone,
    [Parameter(Mandatory=$false,Position=5)]
    [String] $numberHosts = 6

    )

    $NTX = $NTXSubnetID
    $ILO =  $ILOSubnetID
    $VMOTION = $VMOTSubnetID
    
    
    $itemSubs = 'NTXCVM','ILO','VMOTION'
    $valueSubs = $NTX, $ILO, $VMOTION
    $verifiedSubs =@{}
    $e=0


    foreach($value in $valueSubs) { 

    $callSubnetIB = Get-IBObject -ObjectType 'network' -Filters "ipv4addr=$value" 
        if ($callSubnetIB -ne $null){
            Write-Output "Subnet found on Infoblox Database:   " $callSubnetIB.network | Write-Host }
        else{Write-Output "Subnet not found on infoblox Database." |Write-Host
        Break }
         
        $verifiedSubs.Add($itemSubs[$e],$callSubnetIB)
        $e++
}


}

#Creates all DNS records for Nutanix hosts (001 to 006) from given subnets and site code

function New-NTXMetroSetup() {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $ILOSubnetID,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $NTXSubnetID,
    [Parameter(Mandatory=$true,Position=2)]
    [String] $VMOTSubnetID,
    [Parameter(Mandatory=$true,Position=3)]
    [String] $siteCode,
    [Parameter(Mandatory=$False,Position=4)]
    [String] $zone,
    [Parameter(Mandatory=$false,Position=5)]
    [String] $numberHosts

    )

. Check-IBNutanixRanges -ILOSubnetID $ILOSubnetID -NTXSubnetID $NTXSubnetID -VMOTSubnetID $VMOTSubnetID -siteCode $siteCode

    $zone = '.corpnet2d.com'
    $stdNamingIT = 'sxhci00'
    $mngmtID = 'rib'
    $cvmID = 'cvm'
    $rsrvID = '-vmotion'
    #$stdNamingOT = 'osxhci00'
    [System.Collections.ArrayList]$hostList = @()
    $stdClusterName = '_hci_cl00'
    $IpLogTable =@{}
    $logPath = "E:\HDPTools\InfoBlox_Automation\IP_Logs\"+$siteCode+".txt"


     function Set-NutanixILOIPs{
                     
     [System.Collections.ArrayList]$resposiveIPs = @()
     [System.Collections.ArrayList]$availableIPs = @()
          
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Allocation for ILOs..."
            For($hostSeqNum = 1; $hostSeqNum -le 6; $hostSeqNum++) {
                $hostName =$siteCode+$stdNamingIT+$hostSeqNum+$mngmtID
                $hostList.add($hostName) |out-null
                }
             
             Start-Sleep -s 2
             Write-Host "Subnet for ILO is: " $verifiedSubs.ILO.network
             Write-host 'The following Host Names will be allocated.  ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.ILO.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs
         
    #Get the next 6 available IPs for ILO
    
             foreach ($nhost in $hostList) {


                if ($verifiedSubs.ILO -ne $null){
               
                    Do{
                        $nextAvailIP = $verifiedSubs.ILO| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Host "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost + $zone
                            Write-Output "Setting up Host DNS entry with ' $nextAvailIP for $hostFQDN"| Write-Host
                            $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
                            $newHost | New-IBObject -type record:host

                            ##Update extra Attributes

                            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                            $updateHost | Add-Member @{comment='Record created by HD&P script'}
                            $updateHost | Set-IBObject 
                            Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
                
                $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
                }
   
    }

     Set-NutanixILOIPs

     function Set-NutanixMGMTIPs {
 
     [System.Collections.ArrayList]$resposiveIPs = @()
     [System.Collections.ArrayList]$availableIPs = @()
          
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Allocation for Management IPs..."
            For($hostSeqNum = 1; $hostSeqNum -le 6; $hostSeqNum++) {
                $hostName =$siteCode+$stdNamingIT+$hostSeqNum
                $hostList.add($hostName) |out-null
                }
             
             Start-Sleep -s 2
             Write-Host "Subnet for Nutanix Managment and CVM is: " $verifiedSubs.NTXCVM.network
             Write-host 'The following Host Names will be allocated.  ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.NTXCVM.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs

    #Get the next 6 available IPs for Management

             foreach ($nhost in $hostList) {


                if ($verifiedSubs.NTXCVM -ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.NTXCVM| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost + $zone
                            Write-Output "Setting up Host DNS entry with ' $nextAvailIP for $hostFQDN"| Write-Host
    
        	                $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
                            $newHost | New-IBObject -type record:host

                            ##Update extra Attributes

                            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                            $updateHost | Add-Member @{comment='Record created by HD&P script'}
                            $updateHost | Set-IBObject 
                            Write-Host 'Allocated successfully' -ForegroundColor Green
                            

                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
            $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
            }
    
    }

    Set-NutanixMGMTIPs

        function Set-NutanixCVMIPs{
         [System.Collections.ArrayList]$resposiveIPs = @()
         [System.Collections.ArrayList]$availableIPs = @()        
          
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Allocation for CVMs..."
            For($hostSeqNum = 1; $hostSeqNum -le 6; $hostSeqNum++) {
                $hostName =$siteCode+$stdNamingIT+$hostSeqNum+$cvmID
                 $hostList.add($hostName) |out-null
                
                }
             
             Start-Sleep -s 2
             Write-Host "Subnet for Nutanix Managment and CVM is: " $verifiedSubs.NTXCVM.network
             Write-host 'The following Host Names will be allocated.  ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.NTXCVM.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs


    #Get the next 6 available IPs for CVMs

             foreach ($nhost in $hostList) {


                if ($verifiedSubs.NTXCVM -ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.NTXCVM| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost + $zone
                            Write-Output "Setting up Host DNS entry with ' $nextAvailIP for $hostFQDN"| Write-Host
    
        	                $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
                            $newHost | New-IBObject -type record:host

                            ##Update extra Attributes

                            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                            $updateHost | Add-Member @{comment='Record created by HD&P script'}
                            $updateHost | Set-IBObject 
                            Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
            $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
            }
    
    }

    Set-NutanixCVMIPs

        function Set-NutanixClusters{

        [System.Collections.ArrayList]$resposiveIPs = @()
        [System.Collections.ArrayList]$availableIPs = @()      
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Allocation for HCI Clusters..."
            For($hostSeqNum = 1; $hostSeqNum -le 2; $hostSeqNum++) {
                $hostName =$siteCode+$stdClusterName+$hostSeqNum
                $hostList.add($hostName) |out-null
                }
             
             Start-Sleep -s 2
             Write-Host "Subnet for Nutanix Managment and CVM is: " $verifiedSubs.NTXCVM.network
             Write-host 'The following Host Names will be allocated.  ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.NTXCVM.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs


    #Get the next 2 available IPs for clusters

             foreach ($nhost in $hostList) {


                if ($verifiedSubs.NTXCVM-ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.NTXCVM| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost + $zone
                            Write-Output "Setting up Host DNS entry with ' $nextAvailIP for $hostFQDN"| Write-Host
    
        	                $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
                            $newHost | New-IBObject -type record:host

                            ##Update extra Attributes

                            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                            $updateHost | Add-Member @{comment='Record created by HD&P script'}
                            $updateHost | Set-IBObject 
                            Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
            $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
            }
    
    }

    Set-NutanixClusters

        function Set-VmotionReservation{
        [System.Collections.ArrayList]$resposiveIPs = @()
        [System.Collections.ArrayList]$availableIPs = @()
          
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Reservation only for Vmotion..."
            For($hostSeqNum = 1; $hostSeqNum -le 6; $hostSeqNum++) {
                $hostName =$siteCode+$stdNamingIT+$hostSeqNum+$rsrvID
                $hostList.add($hostName) |out-null
                }
 
             Start-Sleep -s 2
             Write-Host "Subnet for VMotion IPs is: " $verifiedSubs.VMOTION.network
             Write-host 'The following reservation names will be created: ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.VMOTION.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs

    #Get the next 6 available IPs for VMotion

             foreach ($nhost in $hostList) {


                if ($verifiedSubs.VMOTION -ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.VMOTION| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost
                            Write-Output "Setting up Reservation ' $nextAvailIP for $hostFQDN"| Write-Host
                            New-IBObject -type fixedaddress -IBObject @{ipv4addr=$nextAvailIP;mac='00:00:00:00:00:00';name=$hostFQDN}
                            Write-Host 'Reserverd successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
            $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
            }
    
    }

    Set-VmotionReservation
    #Log host names and IP addresses allocated
    $IpLogTable.GetEnumerator() | sort Value | Out-File $logPath -Append 
}

#Creates all DNS records for Nutanix hosts (001 to 003) from given subnets and site code

function New-NTX3NodeSetup() {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $ILOSubnetID,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $NTXSubnetID,
    [Parameter(Mandatory=$true,Position=2)]
    [String] $VMOTSubnetID,
    [Parameter(Mandatory=$true,Position=3)]
    [String] $siteCode,
    [Parameter(Mandatory=$False,Position=4)]
    [String] $zone,
    [Parameter(Mandatory=$false,Position=5)]
    [String] $numberHosts

    )

. Check-IBNutanixRanges -ILOSubnetID $ILOSubnetID -NTXSubnetID $NTXSubnetID -VMOTSubnetID $VMOTSubnetID -siteCode $siteCode

    $zone = '.corpnet2d.com'
    $stdNamingIT = 'sxhci00'
    $mngmtID = 'rib'
    $cvmID = 'cvm'
    $rsrvID = '-vmotion'
    #$stdNamingOT = 'osxhci00'
    [System.Collections.ArrayList]$hostList = @()
    $stdClusterName = '_hci_cl00'
    $IpLogTable =@{}
    $logPath = "E:\HDPTools\InfoBlox_Automation\IP_Logs\"+$siteCode+".txt"
    


     function Set-NutanixILOIPs{
                     
     [System.Collections.ArrayList]$resposiveIPs = @()
     [System.Collections.ArrayList]$availableIPs = @()
          
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Allocation for ILOs..."
            For($hostSeqNum = 1; $hostSeqNum -le 3; $hostSeqNum++) {
                $hostName =$siteCode+$stdNamingIT+$hostSeqNum+$mngmtID
                $hostList.add($hostName) |out-null
                }
             
             Start-Sleep -s 2
             Write-Host "Subnet for ILO is: " $verifiedSubs.ILO.network
             Write-host 'The following Host Names will be allocated.  ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.ILO.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs
         
    #Get the next 3 available IPs for ILO
    
             foreach ($nhost in $hostList) {


                if ($verifiedSubs.ILO -ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.ILO| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost + $zone
                            Write-Output "Setting up Host DNS entry with ' $nextAvailIP for $hostFQDN"| Write-Host
    
        	                $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
                            $newHost | New-IBObject -type record:host

                            ##Update extra Attributes

                            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                            $updateHost | Add-Member @{comment='Record created by HD&P script'}
                            $updateHost | Set-IBObject 
                            Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
                $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
                }
   
    }

     Set-NutanixILOIPs

     function Set-NutanixMGMTIPs {
 
     [System.Collections.ArrayList]$resposiveIPs = @()
     [System.Collections.ArrayList]$availableIPs = @()
          
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Allocation for Management IPs..."
            For($hostSeqNum = 1; $hostSeqNum -le 3; $hostSeqNum++) {
                $hostName =$siteCode+$stdNamingIT+$hostSeqNum
                $hostList.add($hostName) |out-null
                }
             
             Start-Sleep -s 2
             Write-Host "Subnet for Nutanix Managment and CVM is: " $verifiedSubs.NTXCVM.network
             Write-host 'The following Host Names will be allocated.  ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.NTXCVM.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs

    #Get the next 3 available IPs for Management

             foreach ($nhost in $hostList) {


                if ($verifiedSubs.NTXCVM -ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.NTXCVM| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost + $zone
                            Write-Output "Setting up Host DNS entry with ' $nextAvailIP for $hostFQDN"| Write-Host
    
        	                $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
                            $newHost | New-IBObject -type record:host

                            ##Update extra Attributes

                            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                            $updateHost | Add-Member @{comment='Record created by HD&P script'}
                            $updateHost | Set-IBObject 
                            Write-Host 'Allocated successfully' -ForegroundColor Green
                            

                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
            $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
            }
    
    }

    Set-NutanixMGMTIPs

        function Set-NutanixCVMIPs{
         [System.Collections.ArrayList]$resposiveIPs = @()
         [System.Collections.ArrayList]$availableIPs = @()        
          
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Allocation for CVMs..."
            For($hostSeqNum = 1; $hostSeqNum -le 3; $hostSeqNum++) {
                $hostName =$siteCode+$stdNamingIT+$hostSeqNum+$cvmID
                 $hostList.add($hostName) |out-null
                
                }
             
             Start-Sleep -s 2
             Write-Host "Subnet for Nutanix Managment and CVM is: " $verifiedSubs.NTXCVM.network
             Write-host 'The following Host Names will be allocated.  ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.NTXCVM.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs


    #Get the next 3 available IPs for CVMs

             foreach ($nhost in $hostList) {


                if ($verifiedSubs.NTXCVM -ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.NTXCVM| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost + $zone
                            Write-Output "Setting up Host DNS entry with ' $nextAvailIP for $hostFQDN"| Write-Host
    
        	                $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
                            $newHost | New-IBObject -type record:host

                            ##Update extra Attributes

                            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                            $updateHost | Add-Member @{comment='Record created by HD&P script'}
                            $updateHost | Set-IBObject 
                            Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
            $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
            }
    
    }

    Set-NutanixCVMIPs

        function Set-NutanixClusters{

        [System.Collections.ArrayList]$resposiveIPs = @()
        [System.Collections.ArrayList]$availableIPs = @()      
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Allocation for HCI Clusters..."
            For($hostSeqNum = 1; $hostSeqNum -le 1; $hostSeqNum++) {
                $hostName =$siteCode+$stdClusterName+$hostSeqNum
                $hostList.add($hostName) |out-null
                }
             
             Start-Sleep -s 2
             Write-Host "Subnet for Nutanix Managment and CVM is: " $verifiedSubs.NTXCVM.network
             Write-host 'The following Host Names will be allocated.  ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.NTXCVM.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs


    #Get the next  available IPs for clusters

             foreach ($nhost in $hostList) {


                if ($verifiedSubs.NTXCVM -ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.NTXCVM| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost + $zone
                            Write-Output "Setting up Host DNS entry with ' $nextAvailIP for $hostFQDN"| Write-Host
    
        	                $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$nextAvailIP } ) }
                            $newHost | New-IBObject -type record:host

                            ##Update extra Attributes

                            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                            $updateHost | Add-Member @{comment='Record created by HD&P script'}
                            $updateHost | Set-IBObject 
                            Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
            $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
            }
    
    }

    Set-NutanixClusters

        function Set-VmotionReservation{
        [System.Collections.ArrayList]$resposiveIPs = @()
        [System.Collections.ArrayList]$availableIPs = @()
          
    #Generate array with host names
            $hostList.Clear()
            Write-Host "Staring IP Reservation only for Vmotion..."
            For($hostSeqNum = 1; $hostSeqNum -le 3; $hostSeqNum++) {
                $hostName =$siteCode+$stdNamingIT+$hostSeqNum+$rsrvID
                $hostList.add($hostName) |out-null
                }
 
             Start-Sleep -s 2
             Write-Host "Subnet for VMotion IPs is: " $verifiedSubs.VMOTION.network
             Write-host 'The following reservation names will be created: ' 
             Write-Host $hostList -foreground green
             
             Read-Host "To continue, press [any key]; to cancel press [Ctrl +c]" 

   #Reserve the first three IPs from every subnet
                
            $getSubnetIPs=$verifiedSubs.VMOTION.network
            $callAllIPs = Get-IBObject -type ipv4address -filters "network=$getSubnetIPs"
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3]
            Write-Output 'IP Address below will not be assgined:' $reservedNDIPs

    #Get the next 6 available IPs for VMotion

             foreach ($nhost in $hostList) {


                if ($verifiedSubs.VMOTION -ne $null){
                    Do{
                        $nextAvailIP = $verifiedSubs.VMOTION| Invoke-IBFunction -name 'next_available_ip' -args @{num=1;exclude=@($resposiveIPs;$availableIPs;$reservedNDIPs)} | Select -expand ips
                        Write-Output "Next available IP(s): $nextAvailIP" | Write-Host

                        foreach ($ipAddress in $nextAvailIP ) {
                            Write-Output "Testing availability of $ipAddress" | Write-Host
                            $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                                If($pingTest -eq $true){
                                    $ipInUse =$ipAddress
                                    $resposiveIPs.Add($ipInUse) | Out-Null
                                     Write-Host "IP Address is in use! Trying next one..." -ForegroundColor Red
                                    } 
                                 else { Write-Host "IP address is available" -ForegroundColor Green | Write-Output
                                        $ipNotInUse=$ipAddress
                                        $availableIPs.Add($ipNotInUse) | Out-Null
                                       }
                       
                         } 
            	    } Until ($pingTest -eq $false)
                
           
                
            
            
                } else{Write-Output "No IPs to display" |Write-Host}

                if($nextAvailIP -ne $null){
   
                ##Set new IBrecord
    
                        try{
                            $hostFQDN = $nhost
                            Write-Output "Setting up Reservation ' $nextAvailIP for $hostFQDN"| Write-Host
                            New-IBObject -type fixedaddress -IBObject @{ipv4addr=$nextAvailIP;mac='00:00:00:00:00:00';name=$hostFQDN}
                            Write-Host 'Reserverd successfully' -ForegroundColor Green
                            
                            }

                        Catch{
                            Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                            Break        
                            }
                        Finally{}
   


                    }
   
                    else{ 
                        Write-Host 'Unable to create entry, Please provide a Valid Subnet Range' -ForegroundColor red
                        }
            $IpLogTable.Add($hostFQDN,$nextAvailIP) | Out-Null
            }
    
    }

    Set-VmotionReservation
    #Log host names and IP addresses allocated
    $IpLogTable.GetEnumerator() | sort Value | Out-File $logPath -Append 
}

#### DEV

function Get-IBIPinfo {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $IPAddress

    )

    $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"
    $callIpObj.types

    }

function Set-IPsfromCSVDEV2 {

[CmdletBinding()] 
Param 
(
[Parameter(Mandatory=$true,Position=0)]
 [String] $filePath,
[Parameter(Mandatory=$true,Position=0)]
[String]$skipPing 
 )


$hostList =@{}
[System.Collections.ArrayList]$resposiveIPs =@()
[System.Collections.ArrayList]$availableIPs=@()
[System.Collections.ArrayList]$inUseIPs =@()
$verifiedhostList =@{}
$counter=0

$hostList = Import-Csv -Path $filePath

Write-Host "The following list of hos will be added:" 
Write-Output $hostList | Format-Table


Write-Host "Allocating" $hostList.IPAddress.Count  "records in total."

Write-Host "Please Notice that this script accept IPs from multiple subnets at the same time" -ForegroundColor Yellow


        foreach ($ip in $hostList.IPAddress ) {
        Write-Host "Record Number $counter ==============" 
            $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$ip"
            if($callIpObj.status -eq 'USED') {
                $inUseIPs.Add($ip) | Out-Null
                Write-Host "There is a record for this IP - $ip with name " $callIpObj.names -ForegroundColor Red
                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                Write-Host "DNS entry with for $hostFQDN was not created " -ForegroundColor Red
                Write-Host "======================="
                }
            elseif($callIpObj.status -eq 'UNUSED'){
                $availableIPs.Add($ip) | Out-Null
                Write-Host " $ip - has no existing records!" -ForegroundColor Green

                if($skipPing-eq $true){

                    Write-Host "Warning!! $ip was not tested for ping response" -ForegroundColor Yellow 

                    ##Set new IBrecord
    
                    try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Host "Setting up Host DNS entry with ' $ip for $hostFQDN" 
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ip } ) }
                                $newHost | New-IBObject -type record:host

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}
                                $updateHost | Set-IBObject 
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                                                 
                               } Finally{} 
                               
               }

               elseif($skipPing-eq $false){

                Write-Host "Performing pin test to $ip" 
                $pingTest = Test-Connection $ipAddress -Count 2 -Quiet

                If($pingTest -eq $true){
                    $resposiveIPs.Add($ip) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    }
                        
                else { 
                     Write-Host "No Response from IP" -ForegroundColor Green | Write-Output
                         
                            ##Set new IBrecord
    
                                try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Output "Setting up Host DNS entry with ' $ip for $hostFQDN"| Write-Host
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ip } ) }
                                $newHost | New-IBObject -type record:host

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}
                                $updateHost | Set-IBObject 
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                            
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               Write-Host "======================="                  
                            }
                        Finally{}
   
                    }
             
   
            }
            
            }
        $counter++
    }
        
        
}


function Set-IPsfromCSVNOTUSE {

[CmdletBinding()] 
Param 
(
[Parameter(Mandatory=$true,Position=0)]
 [String] $filePath,
[Parameter(Mandatory=$true,Position=0)]
[String]$skipPing 
 )


$hostList =@{}
[System.Collections.ArrayList]$resposiveIPs =@()
[System.Collections.ArrayList]$availableIPs=@()
[System.Collections.ArrayList]$inUseIPs =@()
$verifiedhostList =@{}
$counter=0
$IpLogTable =@{}
$logPath = "C:\Test_Scripts\"+$siteCode+".txt"

$hostList = Import-Csv -Path $filePath

Write-Host "The following list of hos will be added:" 
Write-Output $hostList | Format-Table

#. Get-SubnetID -IPAddress $hostList.IPAddress[0] -Netmask $hostList.Netmask[0]


Write-Host "Allocating" $hostList.IPAddress.Count  "records in total."

Write-Host "Checking Subnet for" $hostList.IPAddress[0]  "exist on IB (NOTE: only first Subnet is verified) "

. Check-IBSubnetRange -SubnetID $hostList.IPAddress[0]

#Get all Objects in given subnet, set an array with IPs which already have a record in Infoblox

$callSubnetObj = Get-IBObject -type ipv4address -filters "network=$verifiedSubnetID"

foreach($ip in $callSubnetObj){
    if( $ip.status -eq 'USED'){
            $inUseIPs.add($ip.ip_address) | out-null
     }
}
Write-Host "IPs in use: " $inUseIPs | Format-Table


        foreach ($ipAddress in $hostList.IPAddress ) {

            if($skipPing-eq $true){
                Write-Host "Skiping pinging process for $ipAddress" 
                Write-Host "Checking status"
                $pingTest = $false
                If($pingTest -eq $true){
                    $ipInUse =$ipAddress
                    $resposiveIPs.Add($ipInUse) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    }

                elseif($ipAddress -iin $inUseIPs){
                     $usedIPIB = Get-IBObject -type ipv4address -filters "ip_address=$ipAddress"
                     Write-Host "There a record for this IP with name " $usedIPIB.names -ForegroundColor Red
                     Write-Host "Skipping this DNS entry"
                    }
                        
                else { 
                     Write-Host "IP address is available!" -ForegroundColor Green | Write-Output
                     $ipNotInUse=$ipAddress
      
                            ##Set new IBrecord
    
                                try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Output "Setting up Host DNS entry with ' $ipNotInUse for $hostFQDN"| Write-Host
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ipNotInUse } ) }
                                $newHost | New-IBObject -type record:host

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}
                                $updateHost | Set-IBObject 
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                                                 
                            }
                        Finally{}
   
                    }
        $counter++
            
            }

            else{
                Write-Output "Testing availability and status of $ipAddress" | Write-Host
                $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                If($pingTest -eq $true){
                    $ipInUse =$ipAddress
                    $resposiveIPs.Add($ipInUse) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    }

                elseif($ipAddress -iin $inUseIPs){
                     $usedIPIB = Get-IBObject -type ipv4address -filters "ip_address=$ipAddress"
                     Write-Host "There a record for this IP with name " $usedIPIB.names -ForegroundColor Red
                     Write-Host "Skipping this DNS entry"
                    }
                        
                else { 
                     Write-Host "IP address is available, no ping, no record!" -ForegroundColor Green | Write-Output
                     $ipNotInUse=$ipAddress
      
                            ##Set new IBrecord
    
                                try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Output "Setting up Host DNS entry with ' $ipNotInUse for $hostFQDN"| Write-Host
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ipNotInUse } ) }
                                $newHost | New-IBObject -type record:host

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} 
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}
                                $updateHost | Set-IBObject 
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                            
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                                                 
                            }
                        Finally{}
   
                    }
        $counter++     
            
            }
                    

        }
}

#Reserves Ips (vmotion) from csv file

function Set-ReservfromCSVNOTUSE {

[CmdletBinding()] 
Param 
(
[Parameter(Mandatory=$true,Position=0)]
 [String] $filePath,
[Parameter(Mandatory=$true,Position=0)]
[String]$skipPing 
 )


$hostList =@{}
[System.Collections.ArrayList]$resposiveIPs =@()
[System.Collections.ArrayList]$availableIPs=@()
[System.Collections.ArrayList]$inUseIPs =@()
$verifiedhostList =@{}
$counter=0

$hostList = Import-Csv -Path $filePath

Write-Host "The following list of hos will be added:" 
Write-Output $hostList | Format-Table
Write-Host "Obtaining Network/SubnetID"

#. Get-SubnetID -IPAddress $hostList.IPAddress[0] -Netmask $hostList.Netmask[0]

Write-Host "Allocating" $hostList.IPAddress.Count  "records in total."

Write-Host "Checking Subnet exist on IB (NOTE: only first Subnet is verified) "

. Check-IBSubnetRange -SubnetID $hostList.IPAddress[0]

#Get all Objects in given subnet, set an array with IPs which already have a record in Infoblox

$callSubnetObj = Get-IBObject -type ipv4address -filters "network=$verifiedSubnetID"

foreach($ip in $callSubnetObj){
    if( $ip.status -eq 'USED'){
            $inUseIPs.add($ip.ip_address) | out-null
     }
}
Write-Host "IPs in use: " $inUseIPs | Format-Table


        foreach ($ipAddress in $hostList.IPAddress ) {

            if($skipPing-eq $true){
                Write-Host "Skiping pinging process for $ipAddress" 
                Write-Host "Checking status"
                $pingTest = $false
                If($pingTest -eq $true){
                    $ipInUse =$ipAddress
                    $resposiveIPs.Add($ipInUse) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    }

                elseif($ipAddress -iin $inUseIPs){
                     $usedIPIB = Get-IBObject -type ipv4address -filters "ip_address=$ipAddress"
                     Write-Host "There a record for this IP with name " $usedIPIB.names -ForegroundColor Red
                     Write-Host "Skipping this DNS entry"
                    }
                        
                else { 
                     Write-Host "IP address is available!" -ForegroundColor Green | Write-Output
                     $ipNotInUse=$ipAddress
      
                            ##Set new IBrecord
    
                                try{

                            $hostReservation = $hostList.hostName[$counter]           
                            Write-Output "Setting up Reservation ' $ipNotInUse for $hostReservation"| Write-Host
                            New-IBObject -type fixedaddress -IBObject @{ipv4addr=$ipNotInUse;mac='00:00:00:00:00:00';name=$hostReservation}
                            Write-Host 'Reserverd successfully' -ForegroundColor Green

                           
                            
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                                                 
                            }
                        Finally{}
   
                    }
        $counter++
            
            }

            else{
                Write-Output "Testing availability and status of $ipAddress" | Write-Host
                $pingTest = Test-Connection $ipAddress -Count 2 -Quiet
                If($pingTest -eq $true){
                    $ipInUse =$ipAddress
                    $resposiveIPs.Add($ipInUse) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    }

                elseif($ipAddress -iin $inUseIPs){
                     $usedIPIB = Get-IBObject -type ipv4address -filters "ip_address=$ipAddress"
                     Write-Host "There a record for this IP with name " $usedIPIB.names -ForegroundColor Red
                     Write-Host "Skipping this DNS entry"
                    }
                        
                else { 
                     Write-Host "IP address is available, no ping, no record!" -ForegroundColor Green | Write-Output
                     $ipNotInUse=$ipAddress
      
                            ##Set new IBrecord
    
                                try{

                            $hostReservation = $hostList.hostName[$counter]           
                            Write-Output "Setting up Reservation ' $ipNotInUse for $hostReservation"| Write-Host
                            New-IBObject -type fixedaddress -IBObject @{ipv4addr=$ipNotInUse;mac='00:00:00:00:00:00';name=$hostReservation}
                            Write-Host 'Reserverd successfully' -ForegroundColor Green

                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                                                 
                            }
                        Finally{}
   
                    }
        $counter++     
            
            }
                    

        }
}

function Set-SingleIP {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $IPAddress,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $hostName,
    [Parameter(Mandatory=$true,Position=2)]
    [String] $Zone

    )

   if($zone -eq 'corpnet1.com')
            {$zone='.corpnet1.com'}
    elseif($zone -eq 'corpnet2.com')
            {$zone='.corpnet2.com'}
    else
            {Write-Output "Invalid Zone selected."
             Break}

    $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"
    $callIpObj

    if($callIpObj.status -eq 'USED'){
        Write-Host "There is a record for this IP - $IPAddress with name " $callIpObj.names -ForegroundColor Red
        Write-Host "No record was created" -ForegroundColor Red
        Write-Host "======================="
    }

    else{
      try{
            Write-Output 'Setting up Host DNS entry' | Write-Host
            $hostFQDN = $hostName + $zone
        	$newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$IPAddress } ) }
            $newHost | New-IBObject -type record:host
            ##Update extra Attributes

            $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN"
            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host') 
            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}}
            $updateHost | Add-Member @{comment='Record created by HD&P script'}
            $updateHost | Set-IBObject

            ##### Verification from IB

            $callIpObjcompleted = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"

            Write-Host "DNS Record / IP allocation completed - "$callIpObjcompleted.names " with IPAddress:" $callIpObjcompleted.ip_address -ForegroundColor Green
        }

        Catch{
        Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
        Break        
        }
        Finally{}

    }

}