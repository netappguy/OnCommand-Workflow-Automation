# Module : wfautils v.1.0.1
# 
#Import-Module .\WFAUtils
#Get-WorkflowExecURI -WorkFlowName "Verif Stockage"

#$manifest = @{
#    Path              = '.\WFAUtils\WFAUtils.psd1'
#    RootModule        = 'WFAUtils.psm1' 
#    Author            = 'Marc Ferber'
#	 CompanyName       = 'NetApp'
#	 ModuleVersion     = '1.0.1'
#}
#New-ModuleManifest @manifest

function Import-WFAModules
{
	$REGISTRY = "HKLM:\SOFTWARE\NetApp\WFA"
	$wfalocation = $(Get-ItemProperty $REGISTRY | select -ExpandProperty WFAInstallDir)
	
	if (!(Get-Module -Name "WFA"))
	{
		import-module $($wfalocation + "PoSH\Modules\WFA")
	}
	if (!(Get-Module -Name "WFAWrapper"))
	{
		import-module $($wfalocation + "PoSH\Modules\WFAWrapper")
	}
}

#######################################################################################################################
#
# 	Get-WFAHttpPort
#
#	In this commandlet we extract the http port used by WFA from the registry 
#
#########################################################################################################################
function Get-WFAHTTPPort
{
<#
.SYNOPSIS

Cmdlet to get the WFA http Port.

.DESCRIPTION
Get the WFA Http Port to be able to send rest request.

.EXAMPLE
Get-WFAHttpPort
80

#>

	$REGISTRY = "HKLM:\SOFTWARE\Wow6432Node\Apache Software Foundation\Procrun 2.0\NA_WFA_SRV\Parameters\Java"
	$httpPort = (Get-ItemProperty $REGISTRY |select -ExpandProperty Options|where {$_ -match "-Dhttp.port"}).split("=")[1]
	return $httpPort
}

#######################################################################################################################
#
# 	Get-WFAHttpsPort
#
#	In this commandlet we extract the http port used by WFA from the registry 
#
#########################################################################################################################
function Get-WFAHTTPSPort
{
<#
.SYNOPSIS

Cmdlet to get the WFA https Port.

.DESCRIPTION
Get the WFA Http Port to be able to send rest request.

.EXAMPLE
Get-WFAHttpsPort
443

#>

$REGISTRY = "HKLM:\SOFTWARE\Wow6432Node\Apache Software Foundation\Procrun 2.0\NA_WFA_SRV\Parameters\Java"
$httpsPort = (Get-ItemProperty $REGISTRY |select -ExpandProperty Options|where {$_ -match "-Dhttps.port"}).split("=")[1]
return $httpsPort
}

#######################################################################################################################
#
# 	Format-FSSize
#
#	In this commandlet we change a number to the appriopriate unit size
#
#########################################################################################################################
Function Format-FSSize()
{
<#
.SYNOPSIS

Cmdlet to Format a computer number to a Human readable number.

.DESCRIPTION
Get a Human readable number from a byte number. IE 42.84 GB is more readable than  46000000000 Bytes...

.EXAMPLE
Format-FSSize(46000000000)
Return : 42.84 GB

#>

    Param ([long]$size)

	switch($size) {
	{ $_ -gt 1pb } { return "{0:n2} PB" -f ($_ / 1pb); break }
	{ $_ -gt 1tb } { return "{0:n2} TB" -f ($_ / 1tb); break }
	{ $_ -gt 1gb } { return "{0:n2} GB" -f ($_ / 1gb); break }
	{ $_ -gt 1mb } { return "{0:n2} MB " -f ($_ / 1mb); break }
	{ $_ -gt 1kb } { return "{0:n2} KB " -f ($_ / 1Kb); break }
	default { return "{0} B " -f $_ ; break} 
	}      
}

function Test-IsRunByWFA
{
<#
.SYNOPSIS

Cmdlet to tell if the command was run by WFA or Outside WFA.

.DESCRIPTION
Return True if the command is executed by WFA as part of a Workflow, and False if run outside WFA.
#>

	$RunByWFA=$True	
	try
	{
		Get-WfaCredentials -HostName "CheckCredential" -ErrorAction Stop
	}
	Catch
	{
		if ( $_.Exception.Message -eq "Execution URI input line was not set.")
		{
			$RunByWFA=$false
		}
	}
	Return $RunByWFA
}

function Get-WFALogger
{
<#
.SYNOPSIS

Cmdlet to Log simultaneoussly Information into WFA Log and a File log.

.DESCRIPTION
Let log entry in WFA Log event and in a given file at the same time.

.PARAMETER LogPath

The complete Log File and Path ; if LogPath = !NoLog! then nothing will be written into the file

.PARAMETER Severity

The message Severity to choose from : Info Warn Error

.PARAMETER message
The Message to Log

.EXAMPLE
Get-WFALogger -Info -message "My Message"

#>
param (
	[parameter(Mandatory=$false)]
	[string]$scriptlog,

	[parameter(Mandatory=$true)]
	[string]$message,
	
	[parameter(Mandatory=$false, HelpMessage="Log level : INFO")]
	[switch]$Info,
	
	[parameter(Mandatory=$false, HelpMessage="Log level : Warn")]
	[switch]$Warn,
	
	[parameter(Mandatory=$false, HelpMessage="Log level : ERROR")]
	[switch]$Error
)

	[string]$Severity="Info"
	if ($Error.IsPresent) { $Severity="Error" }
	if ($Warn.IsPresent) { $Severity="Warn" }
	if ($Info.IsPresent) { $Severity="Info" }	

	$TimeStmp=(Get-date -format yyyyMMddHHmmss).ToString()
	
	if (!($scriptlog))
	{
		try
		{
			$scriptlog = Get-WfaWorkflowParameter -Name scriptlog
		}
		Catch
		{
			#if ( $_.Exception.Message -eq "Execution URI input line was not set.")
			#{
			#	write-host $($TimeStmp + " not inside WFA.. cannot get scriptlog variable from Get-WfaWorkflowParameter") -foregroundcolor green
			#} else
			#{
			#	WFA\Get-WFALogger -Info -message ("Cannot get script log location from variable or from WFA because: " + $_.Exception.Message)
			#}
			$WriteToFile=$False
			$scriptlog="!NoLog!"
		}
		if ($scriptlog -ne "!NoLog!")
		{
			$WriteToFile=$True
		}
	}
	if ($WriteToFile)
	{
		$NewLogMessage = $TimeStmp + " " + $Severity.PadLeft(5," ") + " [" + $(Get-WfaRestParameter "commandName") + "] " + $message + "`n"
		Add-Content -Value $NewLogMessage -Path $scriptlog
	}
	
	if (Test-IsRunByWFA)
	{
		switch ($Severity)
		{
			"Info" { WFA\Get-WFALogger -Info -message "$message" }
			"Warn" { WFA\Get-WFALogger -Warn -message "$message" }
			"Error" { WFA\Get-WFALogger -Error -message "$message" }
			default { WFA\Get-WFALogger -Info -message "$message" }
		}
	} else
	{
		switch ($Severity)
		{
			"Info" { write-host "$TimeStmp $message" -foregroundcolor green }
			"Warn"  { write-host "$TimeStmp $message" -foregroundcolor Yellow }
			"Error" { write-host "$TimeStmp $message" -foregroundcolor red }
		}
	}
}

function New-LogFile
{
<#
.SYNOPSIS

Cmdlet to Create a New File log in the specified path (if needed) for it. The name and path are then returned.

.DESCRIPTION
Create a File log (name will be generated by the function) and if needed the path for it. The name and path are then returned.
The generated File name will be composed like this : WorkflowName_WindowsDomain_UserName_yyyyMMddHHmmss_JobId.txt

.PARAMETER LogPath

The complete Path where to create the log file.

.EXAMPLE

$scriptlog = New-LogFile $("C:\program Files\NetApp\WFALogs")

.NOTES
File path will be saved into a global WFA variable named scriptlog and can be retrieved into another command by using the command : $scriptlog = Get-WfaWorkflowParameter -Name scriptlog
#>
param (
	[parameter(Mandatory=$false)]
	[string]$LogPath
)
	if (!($LogPath))
	{
		$LogPath=(Get-WFAInstallDir)+"WorkFlowLogs\" + $(Get-WfaRestParameter "workflowName")
	}
	if (!(Test-Path $LogPath))
	{
		New-Item -ItemType directory -Path $LogPath
	}
	$clogfile = $LogPath + "\" + $(Get-WfaRestParameter "workflowName") + "_"
	$clogfile += $($(Get-WfaRestParameter "userName").Replace("\","_")) + "_"
	$clogfile += $(Get-date -format yyyyMMddHHmmss) + "_"
	$clogfile += $(Get-WfaRestParameter "jobId")
	$clogfile += ".txt"
	if (!(Test-Path $clogfile))
	{
		$Result=New-Item $clogfile -type file -force
	}
	Add-WfaWorkflowParameter -Name scriptlog -Value $clogfile -AddAsReturnParameter $true
	return $clogfile
}

function Add-LogHeader
{
<#
.SYNOPSIS
Cmdlet to print a header with some usefull information about the environment

.DESCRIPTION
Print a header with some useful informations.
#>

	$toolkitver=get-natoolkitversion
	
	Get-WFALogger -Info -message $("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~| Start |~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	Get-WFALogger -Info -message $(" ")
	Get-WFALogger -Info -message $(" Job ID               : " + $(Get-WfaRestParameter "jobId"))
	Get-WFALogger -Info -message $(" Workflow Name        : " + $(Get-WfaRestParameter "workflowName"))
	Get-WFALogger -Info -message $(" Workflow ID          : " + $(Get-WfaRestParameter "workflowId"))
	Get-WFALogger -Info -message $(" Run By               : " + $(Get-WfaRestParameter "userName"))
	Get-WFALogger -Info -message $(" WFA Authority        : " + $env:username)
	Get-WFALogger -Info -message $(" PowerShell version   : " + $PSVersionTable.PSVersion)
	Get-WFALogger -Info -message $(" Toolkit Version      : " + $toolkitver)
	Get-WFALogger -Info -message $(" Loaded Module        : ")
	foreach ($Module in (get-module))
	{
		Get-WFALogger -Info -message $("                        " + $Module.Name + " (Version " + $Module.Version + ")")
	}
	Get-WFALogger -Info -message $(" ")
}

#######################################################################################################################
#
# 	Get-WFAInstallDir
#
#	In this commandlet get the WFA Installation directory, like "C:\Program Files\NetApp\WFA\"
#
#########################################################################################################################
function Get-WFAInstallDir
{
<#
.SYNOPSIS

Cmdlet to Get the Install Location of WFA.

.DESCRIPTION

Return the WFA Installation directory, like : "C:\Program Files\NetApp\WFA\"

.EXAMPLE

$WFAInstallDir = Get-WFAInstallDir

#>

	$REGISTRY = "HKLM:\SOFTWARE\NetApp\WFA"
	$wfalocation = $(Get-ItemProperty $REGISTRY | select -ExpandProperty WFAInstallDir)
	return $wfalocation
}

#######################################################################################################################
#
# 	Invoke-WFABackup
#
#	In this commandlet we initiate a WFA Backup, and get the file saved where we want. We also can choose how many
#   backup we want to keep.
#
#########################################################################################################################
function Invoke-WFABackup
{
<#
.SYNOPSIS

Cmdlet to let you do a manual backup of wfa. It can be used to send the backup to an other WFA server like for DR purpose.

.DESCRIPTION

Create a WFA Database Backup

.EXAMPLE

$WFABackup = Invoke-WFABackup

#>
param 
(    
    [parameter(mandatory=$false, HelpMessage='The number of backup to keep ; default 7')]
    [int]$BkpToKeep = 7,
    [parameter(mandatory=$false, HelpMessage='WFA Credential to be used to launch the Backup. This Credential should point to the WFA server itself and use a backup role type account.')]
    [String]$BckAccount,
    [parameter(mandatory=$false, HelpMessage='The full path of the directory to which the backup should be saved')]
    [String]$Path
)
  
	$httpPort = Get-WFAHTTPPort
	$wfasrv=$("$env:computername").ToLower()

	# If no user was specified to do the backup then use the first credentail that match an account in wfa DB with Backup Role.
	if (!$BckAccount)
	{
		$mysqlrootpwd = Get-WFADBRootPWD
		$BckAccount=(Invoke-MySqlQuery -Query $("select cred.name from wfa.command_credential cred,wfa.user usr where usr.user_role_type='Backup' and cred.user_name = usr.name LIMIT 0,1") -User root -Password $mysqlrootpwd).name
		if (!$BckAccount)
		{
			throw "No WFA credential provided or found in WFA Database. Please create a WFA Account with a Role of 'Backup' by clicking : Execution / Users / New icon and then, affect it to a Credentials pointing to the WFA server itself with : type :other ; Name : the wfa hostname ; login the backup account name you've just created"
		}
	}
	
	# If no path was specified, set the path to wfa-backup directory at the same place as wfa	
	if (!$Path) {
	    $Path = $((Get-WFAInstallDir) -replace ".$") + "-Backups"
	}
	
    if (!(Test-Path $Path))
	{
		# Create the entire directory structure if not already present, suppress unnecessary output
		New-Item $Path -type directory -force  | Out-Null
	}
	
	#Remove extra older backup..
	$PathFileList = Get-ChildItem $Path -name $("wfa_backup_" + $wfasrv + "*.zip")
	if ($PathFileList.Count -gt $BkpToKeep)
	{
		$PathFileList=$PathFileList | Sort-Object -Descending
		for ($i=$BkpToKeep-1;$i -lt $PathFileList.Count;$i++)
		{
			Remove-Item $($Path + "\" + $PathFileList[$i])
		}
	}

    #Create the HTTP Web request Object
    $req = [System.Net.HttpWebRequest]::Create("http://localhost:"+$httpPort+"/rest/backups")
    $req.Credentials = Get-WfaCredentials -HostName $wfasrv

    #Create a new Cookie container
    $req.CookieContainer = New-Object System.Net.CookieContainer
    $filePath = $Path + "\wfa_backup_" + $wfasrv + "_" + $(get-date -f yyyy-MM-dd-hh-mm) + "_.zip"
	Try {
        
		$result = $req.GetResponse()
        
        $totalLength = $result.ContentLength
		$targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $filePath, Create

        $responseStream = $result.GetResponseStream()
        $buffer = new-object byte[] 10KB

        $count = $responseStream.Read($buffer,0,$buffer.length)
        $downloadedBytes = $count
		
        while ($count -gt 0)
            {
                $targetStream.Write($buffer, 0, $count)
                $count = $responseStream.Read($buffer,0,$buffer.length)
                $downloadedBytes = $downloadedBytes + $count
				sleep -Milliseconds 5
            }
        $targetStream.Flush()
        $targetStream.Close()
        $targetStream.Dispose()
        $responseStream.Dispose()
	}
	
	Catch {
		$ErrorMessage = $_.Exception.Message
		if($ErrorMessage.Contains("The remote server returned an error: (401) Unauthorized")) {
			Get-WFALogger -Error -message $("Invalid credentials specified, cannot take a backup")
		}
		else {
			Get-WFALogger -Error -message $ErrorMessage
		}
    }
	return $filePath
}

function Get-WorkflowExecURI
{
<#
.SYNOPSIS

Cmdlet to get an Execution URI for a specific WorkFlow.

.DESCRIPTION
Gives you the URI for a specific Workflow

.PARAMETER WorkFlowName

name of the Workflow to get the URI

.EXAMPLE
Get-WorkflowExecURI -WorkFlowName "My Beautiful workflow"

#>
param (
	[parameter(Mandatory=$true)]
	[string]$WorkFlowName
)
	
	$myWfaCreds = Get-WfaCredentials -Hostname "localhost"
	if (!$myWfaCreds)
	{
		return 1
	}
	else
	{
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        $WfaHTTPPort = Get-WFAHttpPort
        $WfaHTTPSPort = Get-WFAHttpsPort
		$uuid=(Invoke-RestMethod -Method get -Uri $("http://localhost:" + $WfaHTTPPort + "/rest/workflows?name="+ $WorkFlowName.Replace(" ","%20")) -Credential $myWfaCreds).collection.workflow.uuid
		return $("https://" + $env:computername + ":" + $WfaHTTPSPort + "/rest/workflows/" + $uuid + "/jobs/")
	}
}	
	
function Get-WFADBRootPWD
{
<#
.SYNOPSIS

Cmdlet to Get the WFA DataBase Root password.

.DESCRIPTION

Return the WFA Database Root Password

.EXAMPLE

$WFADBRootPWD = Get-WFADBRootPWD

#>

	$REGISTRY = "HKLM:\SOFTWARE\Wow6432Node\Apache Software Foundation\Procrun 2.0\NA_WFA_SRV\Parameters\Java"
	$mysqlrootpwd = (Get-ItemProperty $REGISTRY |select -ExpandProperty Options|where {$_ -match "-Dmysql.password"}).split("=")[1]
	return $mysqlrootpwd
}

export-modulemember -function Get-WFAHTTPPort
export-modulemember -function Get-WFAHTTPSPort
export-modulemember -function Test-IsRunByWFA
export-modulemember -function Get-WFALogger
export-modulemember -function New-LogFile
export-modulemember -function Add-LogHeader
export-modulemember -function Get-WFAInstallDir
export-modulemember -function Get-WFADBRootPWD
export-modulemember -function Format-FSSize
export-modulemember -function Get-WorkflowExecURI
export-modulemember -function Import-WFAModules
export-modulemember -function Invoke-WFABackup
