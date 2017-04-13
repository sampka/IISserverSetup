param([string] $XMLNAME = "\\mi\dfs\Shared\Team IO\The Wolf Pack\Scripts Work in progress\Sam\IISExample.xml", [string] $Enviroment = "ErrorEnviroment")

    #ErrorChecks
    if($XMLNAME -eq "ErrorXML")
    {
    Write-host "No Server Config XML given"
    exit
    }
    elseif(!(Test-Path $XMLNAME))
    {
    Write-host "No Server Config XML File Exsists"
    exit
    }
    if($Enviroment -eq "ErrorEnviroment")
    {
    $Enviroment = read-host "What Enviroment is this for?"
    }

    #Config Variables
    $AppCmd = "$env:windir\system32\inetsrv\appcmd.exe" 
    # Import Server List from XML
    [xml]$ServerSetupinfos = Get-Content "$XMLNAME"                          
    $Sites = $ServerSetupinfos.SelectNodes("/ServerList/Enviroment[@name='$Enviroment']/Site")
    $PWgrp = ($ServerSetupinfos.SelectNodes("/ServerList/Enviroment[@name='$Enviroment']")).GrpMngdPWgrp
    $DirModifyPermissions = ($ServerSetupinfos.SelectNodes("/ServerList/Enviroment[@name='$Enviroment']")).DirModifyPermissions
    $BaseFolders = "Sites","Services"
    $DirModifyPermission1 = $DirModifyPermissions[0] + ":(OI)(CI)M"
    $DirModifyPermission2 = $DirModifyPermissions[1] + ":(OI)(CI)M"
    $DirModifyPermission3 = $DirModifyPermissions[2] + ":(OI)(CI)M"

    write-host $DirModifyPermission1

#Set Page File Size
Function SetPageFileSize
{
    $computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $computersys.AutomaticManagedPagefile = $False
    $computersys.Put()
    $physicalmem = Get-WmiObject Win32_PhysicalMemory
    $pagefile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name='c:\\pagefile.sys'"
    $pagefile.InitialSize = [int]($physicalmem.capacity*.2/1024/1024)
    $pagefile.MaximumSize = [int]($physicalmem.capacity*3/1024/1024)
    $pagefile.Put()
}


#Registry Keys
Function SetRegistry
    {
    set-Itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -name UserAuthentication -value 00000000 -Type DWord
    }

#Install Windows IIS Features
Function SetWindowsIISComponents
    {
    DISM /Online /Enable-Feature /featurename:ActiveDirectory-Powershell /FeatureName:IIS-WebServerRole /FeatureName:IIS-ApplicationDevelopment /FeatureName:IIS-ASP /FeatureName:IIS-ASPNET /FeatureName:IIS-BasicAuthentication /FeatureName:IIS-CommonHttpFeatures /FeatureName:IIS-DefaultDocument /FeatureName:IIS-DigestAuthentication /FeatureName:IIS-DirectoryBrowsing /FeatureName:IIS-HealthAndDiagnostics /FeatureName:IIS-HostableWebCore /FeatureName:IIS-HttpCompressionStatic /FeatureName:IIS-HttpErrors /FeatureName:IIS-HttpLogging /FeatureName:IIS-HttpRedirect /FeatureName:IIS-HttpTracing /FeatureName:IIS-IPSecurity /FeatureName:IIS-ISAPIExtensions /FeatureName:IIS-ISAPIFilter /FeatureName:IIS-LoggingLibraries /FeatureName:IIS-ManagementConsole /FeatureName:IIS-NetFxExtensibility /FeatureName:IIS-Performance /FeatureName:IIS-RequestFiltering /FeatureName:IIS-Security /FeatureName:IIS-ServerSideIncludes /FeatureName:IIS-StaticContent /FeatureName:IIS-WebServerManagementTools /FeatureName:IIS-WebServerRole /FeatureName:IIS-WindowsAuthentication /FeatureName:WAS-ConfigurationAPI /FeatureName:WAS-NetFxEnvironment /FeatureName:WAS-ProcessModel /FeatureName:WAS-WindowsActivationService /FeatureName:NetFx3 /FeatureName:iis-aspnet45 /FeatureName:WCF-TCP-Activation45 /FeatureName:WCF-HTTP-Activation45 /FeatureName:WCF-HTTP-Activation /FeatureName:TelnetClient /all
    }

#Install Blackbox Perfmon
Function SetPerfmon
    {
        if(!(Test-Path -Path C:\PerfLogs\BlackBox.blg))
            {
            logman.exe create counter BlackBox -o "C:\Perflogs\BlackBox" -c "\Cache(*)\*" "\LogicalDisk(*)\*" "\Memory(*)\*" "\Network Interface(*)\*" "\Objects(*)\*" "\Paging File(*)\*" "\PhysicalDisk(*)\*" "\Process(*)\*" "\Processor(*)\*" "\Redirector(*)\*" "\Server(*)\*" "\Server Work Queues(*)\*" "\System(*)\*" --v -f bincirc -max 2000 -si 30 -r -ow -b 01/01/2014 04:00:00AM
            Start-SMPerformanceCollector -CollectorName blackbox
            }
    }

#Install GMSA Accounts
Function SetGMSA
    {
        param($Account)
      
       
      
            New-ADServiceAccount -name $account -DNSHostName "CN=($account),CN=Managed Service Accounts,DC=mi,DC=corp,DC=rockfin,DC=com" -KerberosEncryptionType RC4, AES128, AES256 -ManagedPasswordIntervalInDays 1 -PrincipalsAllowedToRetrieveManagedPassword $PWgrp
            $registered = Get-ADServiceAccount -Filter 'Name -eq $account' | Select Enabled | Format-List
            while ($registered -eq $null)
            {
                sleep 1
                $registered = Get-ADServiceAccount -Filter 'Name -eq $account' | Select Enabled | Format-List
            }
        Install-ADServiceAccount -Identity $account
        test-adserviceaccount $account
        
    }

#Determine individual URLs
# example "ocrservice$($Iurl)"
$bothnumbers =  [regex]::matches($($env:computername), "[/\d+/]")

if(!($bothnumbers)) {
$Datacenter = $bothnumbers.value[0]
}

if(!($bothnumbers)){ 
$Servernumber = $bothnumbers.value[1]
}

    if ($Datacenter -eq 1)
    {
     $Iurl = $Enviroment + "1w" + $Servernumber
    }
    elseif($Datacenter -eq 2)
    {
     $Iurl = $Enviroment + "2w" + $Servernumber
    }
    else
    {
    $Iurl = $null
    }



# Deconstruct Websites and Permissions
Function Deconstruct    
    {
    Import-Module WebAdministration
    Remove-Website *
    Remove-WebAppPool *
    get-SmbShare | Where-Object name -Notlike '*$' | select Name | Remove-SmbShare -Force
    icacls c:\sites /reset /T
    icacls c:\services /reset /T
    }

# Create Directories, Shares, and Permissions
Function SetDirectories
    {
    cd C:\
    foreach($BaseFolder IN $BaseFolders) 
        {
        if(!(Test-Path -Path $BaseFolder ))
            {
            Mkdir $BaseFolder
            }
        }

    icacls sites /grant $DirModifyPermission1 ".\administrators:(OI)(CI)F" ".\users:(OI)(CI)R" $DirModifyPermission2 $DirModifyPermission1
    icacls services /grant $DirModifyPermission1 ".\administrators:(OI)(CI)F" ".\users:(OI)(CI)R" $DirModifyPermission2 $DirModifyPermission3
    New-SmbShare -Name "sites" -Path "C:\sites" -FullAccess Everyone
    New-SmbShare -Name "services" -Path "C:\services" -FullAccess Everyone
    cd C:\Sites
    foreach($Site in $Sites)
        {
        if(!(Test-Path -Path $site.path ))
            {
            
            md $site.path
           
            }
            foreach($SubSite IN $Site.SubSite) 
             {
             cd $Site.path
                 if(!(Test-Path -Path $SubSite.name ))
                  {
                                        
                     Mkdir $SubSite.name
                     
                   }
             cd ..
        }
        }

        
}
   

# Create Server Setup Shortcut
Function SetShortcut
{
    $file = get-childitem $XMLNAME
    $objShell = New-Object -ComObject "Wscript.Shell"
    $objShortcut = $objShell.CreateShortcut('c:\support\Server Setup.lnk')
    $objShortcut.TargetPath = $File.DirectoryName
    $objShortcut.Save()
}

# Create Web Sites 
Function setwebsite
    {
    cd c:\windows\system32\inetsrv
     foreach($Site in $Sites)
        {
        $Sitename = $Site.name
        $SiteBindings = $Site.bindings
        $sitepath = $site.path
        $SiteSrvAct = $Site.SrvAcctName
        $SiteSrvPass = $Site.SrvAcctPass  

        if($site.GrpMngdSrvAcct -eq "true")
        {
        SetGMSA($SiteSrvAct)
        }

        New-WebAppPool $Site.name
        Set-ItemProperty IIS:\AppPools\$Sitename -name processModel -value @{userName="$SiteSrvAct";password="$SiteSrvPass";identitytype=3}
        New-Website -Name $Sitename -ApplicationPool $Sitename -HostHeader $SiteBindings -PhysicalPath c:\sites\$sitepath -Port 80

        if(!($Iurl -eq $null))
        {
        & $AppCmd set site /site.name:$Sitename /+"bindings.[protocol='http',bindingInformation='*:80:$Sitename$($Iurl)']"
        }
        
         if($Site.AnonAuth -eq "true")
             {     
             Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/AnonymousAuthentication -name enabled -value true -location $Sitename
             }
             else
             {
             Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/AnonymousAuthentication -name enabled -value false -location $Sitename
             }
         if($Site.WindowsAuth -eq "true")
             {         
             Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/windowsAuthentication -name enabled -value true -location $Sitename
             }
             else
             {
             Set-WebConfigurationProperty -filter /system.WebServer/security/authentication/windowsAuthentication -name enabled -value false -location $Sitename
             }

              if($Site.dotnet -eq "2.0")
                  {
                    Set-ItemProperty IIS:\AppPools\$Sitename managedRuntimeVersion v2.0
                   }
                   else
                   {
                   Set-ItemProperty IIS:\AppPools\$Sitename managedRuntimeVersion v4.0
                   }

             foreach($SubSite IN $Site.SubSite) 
                                     {
                     $SubSitename = $SubSite.name
                     $SubSiteBindings = $Site.bindings
                     $SubSiteSrvAct = $Subsite.SrvAcctName
                     $SubSiteSrvPass = $Subsite.SrvAcctPass
                     
                    if($SubSite.GrpMngdSrvAcct -eq "true")
                         {
                          SetGMSA($SubSiteSrvAct)
                         }
                   
                  New-WebAppPool $SubSitename
                  Set-ItemProperty IIS:\AppPools\$SubSitename -name processModel -value @{userName="$SubSiteSrvAct";password="$SubSiteSrvPass";identitytype=3}
                  New-Webapplication -Name $SubSitename -Site $Sitename -ApplicationPool $SubSitename -PhysicalPath c:\sites\$sitepath\$SubSitename


                  if($SubSite.dotnet -eq "2.0")
                  {
                    Set-ItemProperty IIS:\AppPools\$SubSitename managedRuntimeVersion v2.0
                   }
                   else
                   {
                   Set-ItemProperty IIS:\AppPools\$SubSitename managedRuntimeVersion v4.0
                   }

             }
        }



# Set AppPool Defaults, Recycle Times, and Enable Preload
    $websites = Get-ChildItem IIS:\sites -Name
    $AppPools = Get-ChildItem IIS:\apppools -Name
    if ($env:computername -like 'TS2*')
        {
        $Minute = 30
        }
    else
        {
        $minute = 00
        }
    foreach($A in $Apppools)
        {
        set-itemproperty -path IIS:\apppools\$A recycling.periodicRestart.privateMemory -Value 3000000
        set-itemproperty -path IIS:\apppools\$A cpu.limit -Value 60000
        set-itemproperty -path IIS:\apppools\$A cpu.action -Value KILLw3wp3
        set-itemproperty -path IIS:\apppools\$A processModel.idleTimeout -value 00:00:00
        set-itemproperty -path IIS:\apppools\$A recycling.periodicRestart.time -value 00:00:00
        set-itemproperty -path IIS:\apppools\$A recycling.periodicRestart.schedule -value @{value="03:$($minute):00"}
        $Minute++
        }
    foreach($W in $websites)
        {
        set-itemproperty -path IIS:\sites\$W -name applicationDefaults.preloadEnabled -value True
        }

    # appcmd is better at setting the machine key... don't judge
    & $appcmd set config /commit:WEBROOT /section:machineKey /decryption:"AES" /decryptionKey:"C462D6C0AEAFEA64B6F78953CDC301A1969BA77012A9C8BA" /validation:"SHA1" /validationKey:"67D27D17395F88B63E91E3F1E3330F8E0641A774A4ADF57F18765E42E73EB81A6DDB8DC00A7614BF046AB1274A0EB5946CAB217EE8392C1424DBF9D0F966AEBC"
    }

SetRegistry
Write-host  "Registry Set"
SetWindowsIISComponents
Write-host  "DISM Set"
SetPerfmon
write-host "Perfmon Set"
Deconstruct
write-host "Deconstruct Done"
SetDirectories
write-host "Directories Set"
SetShortcut
write-host "ShortCut Created"
setwebsite
write-host "Website Completed"