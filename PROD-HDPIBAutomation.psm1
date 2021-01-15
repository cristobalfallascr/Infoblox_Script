#Version 1.0 for Production Infoblox

Write-Host "Version 1.1 - Production Infoblox - [GRIDNAME]"
 ##Custom Functions

#Login and establishes session to the Infobloc Web API
function Set-IBSession {
    Set-IBConfig -ProfileName 'mygrid' -WAPIHost '[hostname here ##]' -WAPIVersion 'latest' `
    -Credential (Get-Credential) -SkipCertificateCheck
    Write-Host "======== Session establised ==========" -ForegroundColor Green
    Get-IBConfig
    }

# Get information on specific IP
function Get-IBIPinfo {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $IPAddress

    )

    $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress" #-ReturnAllFields
    $callIpObj
    #$callIpObj | ConvertTo-Json -Depth 5

    }

#Calculate a subnet ID from a given IP
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
    $ipCalc = "C:\Test_Scripts\ipcalc.ps1"
	$getSubnetInfo = Invoke-Expression "$ipCalc $argumentList"
    $subnetID = $getSubnetInfo.Network
    $hostMinimum = $getSubnetInfo.HostMin
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
            Write-Host "Subnet found on Infoblox Database:   " $subnetIB.network
            Write-Host "Comment / Description:   " $subnetIB.comment
            $verifiedSubnetID = $subnetIB.network 
        }
        else{
        
        $ipObject = Get-IBObject -type ipv4address -filters "ip_address=$SubnetID"
        $ipObjectSubnet =$ipObject.network
        $subnetIB = Get-IBObject -ObjectType 'network' -Filters "ipv4addr=$ipObjectSubnet"
        Write-Host "Warning!! Subnet not found on infoblox Database" -ForegroundColor Yellow
        Write-Host "Provided IP $SubnetID is part of Subnet" $subnetIB.network
        Write-Host "Comment / Description:   " $subnetIB.comment
        $verifiedSubnetID = $subnetIB.network 
        }
        
        return($verifiedSubnetID)
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
  [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
function Set-NextAvailableIP{
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

    if($zone -eq '.com')
            {$zone='..com'}
    elseif($zone -eq '.com')
            {$zone='..com'}
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
    #[Parameter(Mandatory=$false,Position=1)]
    #[String] $Zone,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $subnetID
    )

   

 
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
            Write-Output "Subnet found on Infoblox Database:   " $callSubnetIB.network | Write-Host
            Write-Host "Subnet found on Infoblox Database:   " $callSubnetIB.network
            Write-Host "Comment / Description:   " $callSubnetIB.comment  }
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

    $zone = '.com'
    $stdNamingIT = ''
    $mngmtID = ''
    $cvmID = ''
    $rsrvID = '-'
    #$stdNamingOT = ''
    [System.Collections.ArrayList]$hostList = @()
    $stdClusterName = ''
    $IpLogTable =@{}
    $logPath = "C:\Test_Scripts\"+$siteCode+".txt"


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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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

    $zone = '.'
    $stdNamingIT = ''
    $mngmtID = ''
    $cvmID = ''
    $rsrvID = '-'
    #$stdNamingOT = ''
    [System.Collections.ArrayList]$hostList = @()
    $stdClusterName = ''
    $IpLogTable =@{}
    $logPath = "C:\Test_Scripts\"+$siteCode+".txt"
    


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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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
            [System.Collections.ArrayList]$reservedNDIPs = $callAllIPs.ip_address[1,2,3,4]
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

#check information about IP
function Get-IBIPinfo {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $IPAddress

    )

    $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"
    $callIpObj
    Write-Host "===== Description Field======"
    $callIpObj.ip_address
    $callIpObj.names 

    }

# Creates DNS records using list from CSV. IPs are predefined on the csv file
function Set-IPsfromCSV {

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


       $allocationLog = foreach ($ip in $hostList.IPAddress ) {
            Write-Host "Record Number $counter ==============" 
            $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$ip"
            if($callIpObj.status -eq 'USED') {
                $inUseIPs.Add($ip) | Out-Null
                Write-Host "There is a record for this IP - $ip with name " $callIpObj.names -ForegroundColor Red
                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                Write-Host "DNS entry with for $hostFQDN was not created " -ForegroundColor Red
                $comment = "There is a record for this IP in IB"
                $status = "Not Completed"
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
                                $newHost | New-IBObject -type record:host | Out-Null

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}| Out-Null
                                $updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               $comment = "This hostname already exists"
                               $status = "Not Completed"
                               Write-Host "======================="                     
                               } Finally{} 
                               
               }

               elseif($skipPing-eq $false){

                Write-Host "Performing ping test to $ip" 
                $pingTest = Test-Connection $ip -Count 2 -Quiet

                If($pingTest -eq $true){
                    $resposiveIPs.Add($ip) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    $comment = "IP responded to Ping, In Use"
                    $status = "Not Completed"
                    }
                        
                else { 
                     Write-Host "No Response from IP" -ForegroundColor Green | Write-Output
                         
                            ##Set new IBrecord
    
                                try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Host "Setting up Host DNS entry with $ip for $hostFQDN" 
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ip } ) }
                                $newHost | New-IBObject -type record:host | Out-Null

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                $updateHost | Add-Member @{comment='Record created by HD&P script'} | Out-Null
                                $updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                            
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               $comment = "This hostname already exists"
                               $status = "Not Completed"
                               Write-Host "======================="                  
                            }
                        Finally{}
   
                    }
             
   
            }
            
           }
        
    $results = '' | SELECT Line,ServerName,IPAddress,Status,Comment
    $results.Line = $counter
    $results.serverName = $hostList.hostName[$counter]
    $results.IPAddress = $hostList.IPAddress[$counter]
    $results.Status = $status
    $results.Comment = $comment
    $results
    $counter++
    } 
   $logname = '_log.txt'
   $logpath = $filePath+$logname
   $allocationLog | FT -auto | Out-File $logpath     
}

# Creates reservation records using list from CSV. IPs are predefined on the csv file
function Set-ReservfromCSV {

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
                Write-Host "Reservation for $hostFQDN was not created " -ForegroundColor Red
                Write-Host "======================="
                }
            elseif($callIpObj.status -eq 'UNUSED'){
                $availableIPs.Add($ip) | Out-Null
                Write-Host " $ip - has no existing records!" -ForegroundColor Green

                if($skipPing-eq $true){

                    Write-Host "Warning!! $ip was not tested for ping response" -ForegroundColor Yellow 

                    ##Set new IBrecord
    
                                try{

                            $hostReservation = $hostList.hostName[$counter]           
                            Write-Output "Setting up Reservation ' $ip for $hostReservation"| Write-Host
                            New-IBObject -type fixedaddress -IBObject @{ipv4addr=$ip ;mac='00:00:00:00:00:00';name=$hostReservation}
                            Write-Host 'Reserverd successfully' -ForegroundColor Green

                                Write-Host "======================="
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                                                 
                               } Finally{} 
                               
               }

               elseif($skipPing-eq $false){

                Write-Host "Performing pin test to $ip" 
                $pingTest = Test-Connection $ip -Count 2 -Quiet

                If($pingTest -eq $true){
                    $resposiveIPs.Add($ip) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    }
                        
                else { 
                     Write-Host "No Response from IP" -ForegroundColor Green | Write-Output
                         
                            ##Set new IBrecord
                    try{

                            $hostReservation = $hostList.hostName[$counter]           
                            Write-Output "Setting up Reservation ' $ip for $hostReservation"| Write-Host
                            New-IBObject -type fixedaddress -IBObject @{ipv4addr=$ip ;mac='00:00:00:00:00:00';name=$hostReservation}
                            Write-Host 'Reserverd successfully' -ForegroundColor Green
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

#set a single record with pre-definedIP
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

   if($zone -eq '')
            {$zone='..'}
    elseif($zone -eq '.com')
            {$zone='..com'}
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

#check to what subnet an IP belongs to
function Get-IBSubnet {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $IPAddress

    )

    $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"
    $verifiedSubnet = $callIpObj.network
    $subnetDetail = Get-IBObject -ObjectType 'network' -Filters "ipv4addr=$verifiedSubnet"
    Write-Host "The IP" $IPAddress "belongs to subnet" $callIpObj.network
    Write-Host "Subnet Description: "$subnetDetail.comment 
    }
  
function Get-CustomRange {

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
    $customRange = $getSubnetInfo.Network
    $hostMin = $getSubnetInfo.HostMin
    $hostMax = $getSubnetInfo.HostMax
        

    Write-Host "Custom Range range for this IP is " $customRange -ForegroundColor Green
    Write-host "====================================================" 

    
    $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"
    $verifiedSubnet = $callIpObj.network
    $subnetDetail = Get-IBObject -ObjectType 'network' -Filters "ipv4addr=$verifiedSubnet"
    Write-Host "The IP" $IPAddress "belongs to subnet" $callIpObj.network -ForegroundColor Yellow
    Write-Host "Subnet Description: "$subnetDetail.comment 
    Write-host "====================================================" 

    $callIpList=Get-IBObject -type ipv4address -filters "ip_address>=$hostMin","ip_address<=$hostMax"
    Write-Host "===================================================="
     Write-Host "=== Free IPs Below ====="  
        foreach($ip in $callIpList){
   

            if($ip.status -eq 'UNUSED'){
        
            Write-Host $ip.ip_address "--" $ip.status
            }
        }

    }

function Get-AnyRangeFreeIPs {

[CmdletBinding()] 
 Param 
    (
    [Parameter(Mandatory=$true,Position=0)]
    [String] $firstIP,
    [Parameter(Mandatory=$true,Position=1)]
    [String] $lastIP
    )
    
    $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$firstIP"
    $verifiedSubnet = $callIpObj.network
    $subnetDetail = Get-IBObject -ObjectType 'network' -Filters "ipv4addr=$verifiedSubnet"
    Write-Host "The IP" $IPAddress "belongs to subnet" $callIpObj.network
    Write-Host "Subnet Description: "$subnetDetail.comment 


    $callIpList=Get-IBObject -type ipv4address -filters "ip_address>=$firstIP","ip_address<=$lastIP"
        foreach($ip in $callIpList){
   

            if($ip.status -eq 'UNUSED'){
        
            Write-Host $ip.ip_address "--" $ip.status
            }
        }

    }

function Get-UsedIPs {

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
    $customRange = $getSubnetInfo.Network
    $hostMin = $getSubnetInfo.HostMin
    $hostMax = $getSubnetInfo.HostMax
        

    Write-Host "Custom Range range for this IP is " $customRange -ForegroundColor Green
    Write-host "====================================================" 

    
    $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"
    $verifiedSubnet = $callIpObj.network
    $subnetDetail = Get-IBObject -ObjectType 'network' -Filters "ipv4addr=$verifiedSubnet"
    Write-Host "The IP" $IPAddress "belongs to subnet" $callIpObj.network -ForegroundColor Yellow
    Write-Host "Subnet Description: "$subnetDetail.comment 
    Write-host "====================================================" 

    $callIpList=Get-IBObject -type ipv4address -filters "ip_address>=$hostMin","ip_address<=$hostMax"
    Write-Host "===================================================="
     Write-Host "=== Used IPs Below ====="  
        foreach($ip in $callIpList){
   

            if($ip.status -eq 'USED'){
        
            Write-Host $ip.ip_address "--" $ip.status "--" $ip.names
            }
        }

    }

#Delete a host record with script (One record at the time only)
function Remove-IBHost {

        [CmdletBinding()] 
     Param 
        (

        [Parameter(Mandatory=$false,Position=1)]
        [String] $hostName
        )
        $verifiedhostName = Resolve-DnsName -Name $hostName
        Write-host "The DNS resolved name is" $verifiedhostName.name
                
        if($hostName -ne $null) {
            $searchHost = Get-IBObject -type record:host -filters "name:~=$hostName"
            Write-Host  "Infoblox reports host " $searchHost.name "with IP" $searchHost.ipv4Addrs.ipv4addr
            $IPAddress = $searchHost.ipv4Addrs.ipv4addr
            Write-Host "proceed to delete??" -ForegroundColor Yellow
            Read-Host 
            $searchHost | Remove-IBObject

            Write-Host "Removed" -ForegroundColor Green
            $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"
            $callIpObj.ip_address
            $callIpObj.names
            

        }
    }

#Check specific host name


function Get-IBHost {

        [CmdletBinding()] 
     Param 
        (

        [Parameter(Mandatory=$false,Position=1)]
        [String] $hostName
        )
        $verifiedhostName = Resolve-DnsName -Name $hostName
        Write-host "The DNS resolved name is" $verifiedhostName.name
                
        if($hostName -ne $null) {
            $searchHost = Get-IBObject -type record:host -filters "name:~=$hostName"
            Write-Host  "Infoblox reports host " $searchHost.name "with IP" $searchHost.ipv4Addrs.ipv4addr
            $IPAddress = $searchHost.ipv4Addrs.ipv4addr
            
            $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"
            $callIpObj
                       

        }
    }


    #New-IBObject -type record:ptr -IBObject @{ipv4addr='10.139.11.112'; ptrdname="ssawntest300"}

function Set-PTR {

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

   if($zone -eq '.com')
            {$zone='..com'}
    elseif($zone -eq '.com')
            {$zone='..com'}
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
     
            Write-Host 'Setting up PTR entry' 
            $hostFQDN = $hostName + $zone
        	$newHost = @{ ptrdname=$hostFQDN;ipv4addr=$IPAddress}
            $newHost | New-IBObject -type record:ptr

            ##Update extra Attributes

            $updateHost = Get-IBObject 'record:ptr' -Filters "name=$hostFQDN"
            $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host') 
            $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}}
            $updateHost | Add-Member @{comment='Record created by HD&P script'}
            $updateHost | Set-IBObject

            ##### Verification from IB

            $callIpObjcompleted = Get-IBObject -type ipv4address -filters "ip_address=$IPAddress"

            Write-Host "PTR Record / IP allocation completed - "$callIpObjcompleted.names " with IPAddress:" $callIpObjcompleted.ip_address -ForegroundColor Green
        }

    
   }

function Set-PTRfromCSV {

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


       $allocationLog = foreach ($ip in $hostList.IPAddress ) {
            Write-Host "Record Number $counter ==============" 
            $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$ip"
            if($callIpObj.status -eq 'none') {
                $inUseIPs.Add($ip) | Out-Null
                Write-Host "There is a record for this IP - $ip with name " $callIpObj.names -ForegroundColor Red
                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                Write-Host "DNS entry with for $hostFQDN was not created " -ForegroundColor Red
                $comment = "There is a record for this IP in IB"
                $status = "Not Completed"
                Write-Host "======================="
                }
            else{
                $availableIPs.Add($ip) | Out-Null
                Write-Host " $ip - has no existing records!" -ForegroundColor Green

                if($skipPing-eq $true){

                    Write-Host "Warning!! $ip was not tested for ping response" -ForegroundColor Yellow 

                    ##Set new IBrecord
    
             
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Host "Setting up Host PTR entry for $ip with name $hostFQDN" 
                                $newHost = @{ ptrdname=$hostFQDN;ipv4addr=$ip}
                                $newHost | New-IBObject -type record:ptr

                                ##Update extra Attributes

                                #$updateHost = Get-IBObject 'record:ptr' -Filters "name=$hostFQDN" 
                                #$updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                #$updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                #$updateHost | Add-Member @{comment='Record created by HD&P script'}| Out-Null
                                #$updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                                


                               
               }

               elseif($skipPing-eq $false){

                Write-Host "Performing ping test to $ip" 
                $pingTest = Test-Connection $ip -Count 2 -Quiet

                If($pingTest -eq $true){
                    $resposiveIPs.Add($ip) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    $comment = "IP responded to Ping, In Use"
                    $status = "Not Completed"
                    }
                        
                else { 
                     Write-Host "No Response from IP" -ForegroundColor Green | Write-Output
                         
                    ##Set new IBrecord
    
                    try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Host "Setting up Host PTR entry for $ip with name $hostFQDN" 
        	                    $newHost = @{ ptrdname=$hostFQDN;ipv4addr=$IPAddress}
                                 $newHost | New-IBObject -type record:ptr

                                ##Update extra Attributes

                                #$updateHost = Get-IBObject 'record:ptr' -Filters "name=$hostFQDN" 
                                #$updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                #$updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                #$updateHost | Add-Member @{comment='Record created by HD&P script'}| Out-Null
                                #$updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               $comment = "This hostname already exists"
                               $status = "Not Completed"
                               Write-Host "======================="                     
                               } Finally{} 
   
                    }
             
   
            }
            
           }
        
    $results = '' | SELECT Line,ServerName,IPAddress,Status,Comment
    $results.Line = $counter
    $results.serverName = $hostList.hostName[$counter]
    $results.IPAddress = $hostList.IPAddress[$counter]
    $results.Status = $status
    $results.Comment = $comment
    $results
    $counter++
    } 
   $logname = '_log.txt'
   $logpath = $filePath+$logname
   $allocationLog | FT -auto | Out-File $logpath     
}

function Set-ISE {

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


       $allocationLog = foreach ($ip in $hostList.IPAddress ) {
            Write-Host "Record Number $counter ==============" 
            $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$ip"
            if($callIpObj.status -eq 'none') {
                $inUseIPs.Add($ip) | Out-Null
                Write-Host "There is a record for this IP - $ip with name " $callIpObj.names -ForegroundColor Red
                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                Write-Host "DNS entry with for $hostFQDN was not created " -ForegroundColor Red
                $comment = "There is a record for this IP in IB"
                $status = "Not Completed"
                Write-Host "======================="
                }
            else{
                $availableIPs.Add($ip) | Out-Null
                Write-Host " $ip - has no existing records!" -ForegroundColor Green

                if($skipPing-eq $true){

                    Write-Host "Warning!! $ip was not tested for ping response" -ForegroundColor Yellow 

                    ##Set new IBrecord
    
                    try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Host "Setting up Host DNS entry with ' $ip for $hostFQDN" 
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ip } ) }
                                $newHost | New-IBObject -type record:host | Out-Null

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}| Out-Null
                                $updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               $comment = "This hostname already exists"
                               $status = "Not Completed"
                               Write-Host "======================="                     
                               } Finally{} 
                               
               }

               elseif($skipPing-eq $false){

                Write-Host "Performing ping test to $ip" 
                $pingTest = Test-Connection $ip -Count 2 -Quiet

                If($pingTest -eq $true){
                    $resposiveIPs.Add($ip) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    $comment = "IP responded to Ping, In Use"
                    $status = "Not Completed"
                    }
                        
                else { 
                     Write-Host "No Response from IP" -ForegroundColor Green | Write-Output
                         
                            ##Set new IBrecord
    
                                try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Host "Setting up Host DNS entry with $ip for $hostFQDN" 
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ip } ) }
                                $newHost | New-IBObject -type record:host | Out-Null

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                $updateHost | Add-Member @{comment='Record created by HD&P script'} | Out-Null
                                $updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                            
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               $comment = "This hostname already exists"
                               $status = "Not Completed"
                               Write-Host "======================="                  
                            }
                        Finally{}
   
                    }
             
   
            }
            
           }
        
    $results = '' | SELECT Line,ServerName,IPAddress,Status,Comment
    $results.Line = $counter
    $results.serverName = $hostList.hostName[$counter]
    $results.IPAddress = $hostList.IPAddress[$counter]
    $results.Status = $status
    $results.Comment = $comment
    $results
    $counter++
    } 
   $logname = '_log.txt'
   $logpath = $filePath+$logname
   $allocationLog | FT -auto | Out-File $logpath     
}
     
#$cred=Get-Credential
#$sess = New-PSSession -Credential $cred -ComputerName s
#Enter-PSSession $sess
#<Run commands in remote session>
#Exit-PSSession
#Remove-PSSession $sess

    


function Set-IPsfromCSV-HCL {

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


       $allocationLog = foreach ($ip in $hostList.IPAddress ) {
            Write-Host "Record Number $counter ==============" 
            $callIpObj = Get-IBObject -type ipv4address -filters "ip_address=$ip"
            if($callIpObj.status -eq 'USED') {
                if($skipPing-eq $true){

                    Write-Host "Warning!! $ip was not tested for ping response" -ForegroundColor Yellow 

                    ##Set new IBrecord
    
                    try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Host "Setting up Host DNS entry with ' $ip for $hostFQDN" 
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ip } ) }
                                $newHost | New-IBObject -type record:host | Out-Null

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}| Out-Null
                                $updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               $comment = "This hostname already exists"
                               $status = "Not Completed"
                               Write-Host "======================="                     
                               } Finally{} 
                               
               }
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
                                $newHost | New-IBObject -type record:host | Out-Null

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                $updateHost | Add-Member @{comment='Record created by HD&P script'}| Out-Null
                                $updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               $comment = "This hostname already exists"
                               $status = "Not Completed"
                               Write-Host "======================="                     
                               } Finally{} 
                               
               }

               elseif($skipPing-eq $false){

                Write-Host "Performing ping test to $ip" 
                $pingTest = Test-Connection $ip -Count 2 -Quiet

                If($pingTest -eq $true){
                    $resposiveIPs.Add($ip) |Out-Null
                    Write-Host "IP Address responded to ping, skipping this entry" -ForegroundColor Red
                    $comment = "IP responded to Ping, In Use"
                    $status = "Not Completed"
                    }
                        
                else { 
                     Write-Host "No Response from IP" -ForegroundColor Green | Write-Output
                         
                            ##Set new IBrecord
    
                                try{
                                $hostFQDN = $hostList.hostName[$counter]+$hostList.zone[$counter]
                                Write-Host "Setting up Host DNS entry with $ip for $hostFQDN" 
          	                    $newHost = @{ name=$hostFQDN; ipv4addrs=@( @{ ipv4addr=$ip } ) }
                                $newHost | New-IBObject -type record:host | Out-Null

                                ##Update extra Attributes

                                $updateHost = Get-IBObject 'record:host' -Filters "name=$hostFQDN" 
                                $updateHost.ipv4addrs[0].PSObject.Properties.Remove('host')  
                                $updateHost | Set-IBObject -template @{extattrs=@{Ticket=@{value='HDP_Script'}}} | Out-Null
                                $updateHost | Add-Member @{comment='Record created by HD&P script'} | Out-Null
                                $updateHost | Set-IBObject | Out-Null
                                $comment = "Allocated successfully"
                                $status = "Successfull"
                                Write-Host 'Allocated successfully' -ForegroundColor Green
                                Write-Host "======================="
                            
                                }

                               Catch{
                               Write-host "Error: the specified host name and DNS record already exist" -ForegroundColor Red
                               $comment = "This hostname already exists"
                               $status = "Not Completed"
                               Write-Host "======================="                  
                            }
                        Finally{}
   
                    }
             
   
            }
            
           }
        
    $results = '' | SELECT Line,ServerName,IPAddress,Status,Comment
    $results.Line = $counter
    $results.serverName = $hostList.hostName[$counter]
    $results.IPAddress = $hostList.IPAddress[$counter]
    $results.Status = $status
    $results.Comment = $comment
    $results
    $counter++
    } 
   $logname = '_log.txt'
   $logpath = $filePath+$logname
   $allocationLog | FT -auto | Out-File $logpath     
}


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
