param (
	[parameter(Mandatory=$false, HelpMessage="Include the table dump for playground database tables.")]
	[boolean]$include_pg_dump=$false,

	[parameter(Mandatory=$false, HelpMessage="Include the table dump for playground database tables even for large one (> max_pg_MBdumpsize=10 MB).")]
	[boolean]$include_pg_large_dump=$false,

	[parameter(Mandatory=$false, HelpMessage="Limit the table dump in MB for playground database tables larger than this value; default 10 MB.")]
	[int]$max_pg_MBdumpsize=10,

	[parameter(Mandatory=$false, HelpMessage="Print all debug informations")]
	[boolean]$dbg=$false
)

$wfadocsv="420"
$wfaversion=Get-WfaVersion
Get-WFALogger -Info -message $(" [>] WFA Version '" + $wfaversion + "' found! will adapt output for that version.")
$wfalocation = [System.IO.Path]::GetFullPath($(Get-ItemProperty "HKLM:\SOFTWARE\NetApp\WFA" | select -ExpandProperty WFAInstallDir) + "..\WFADocs_export\")
if (!(Test-Path $wfalocation))
{
	New-Item $wfalocation -type directory
	$item = gi -literalpath $wfalocation 
	$acl = $item.GetAccessControl() 
	$permission = "Everyone","FullControl","ContainerInherit,Objectinherit","none","Allow"
	#$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","full","ContainerInherit,Objectinherit","none","Allow")
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
	$acl.SetAccessRule($rule)
	$item.SetAccessControl($acl)
}

$ZipFile=[System.IO.Path]::GetFullPath($($wfalocation+"..\WFADocs_export.zip"))
if (Test-Path $ZipFile)
{
	remove-item $ZipFile
}
$wfadbaccount="root"
$wfadbpwd = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Apache Software Foundation\Procrun 2.0\NA_WFA_SRV\Parameters\Java" |select -ExpandProperty Options|where {$_ -match "-Dmysql.password"}).split("=")[1]

Get-WFALogger -Info -message $(" [ ] Starting Export of WFA Configuration !")
$query="select config_key,config_value,description from wfa.global_config order by config_key"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_config=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_config=$wfa_config[1..($wfa_config[0]+1)]
$wfa_config | Export-Csv -Path $($wfalocation + "wfa_config.csv")
$OS='"operating.system","'+(gwmi win32_operatingsystem).caption+'",""'
Get-WFALogger -Info -message $("        [>] Adding conf parameter: " + $OS)
Add-Content $($wfalocation + "wfa_config.csv") $OS
$SrvName='"server.name","'+$env:computername+'",""'
Get-WFALogger -Info -message $("        [>] Adding conf parameter: " + $SrvName)
Add-Content $($wfalocation + "wfa_config.csv") $SrvName
$SrvIP='"server.ipaddress","'+(([System.Net.DNS]::GetHostAddresses($env:computername)|Where-Object {$_.AddressFamily -eq "InterNetwork"} | select-object IPAddressToString)[0].IPAddressToString)+'",""'
Get-WFALogger -Info -message $("        [>] Adding conf parameter: " + $SrvIP)
Add-Content $($wfalocation + "wfa_config.csv") $SrvIP
$Srvfqdn='"server.fqdn","'+(([System.Net.Dns]::GetHostByName(($env:computerName))).HostName)+'",""'
Get-WFALogger -Info -message $("        [>] Adding conf parameter: " + $Srvfqdn)
Add-Content $($wfalocation + "wfa_config.csv") $Srvfqdn
$wfadocversion='"wfa.docs.version","'+$wfadocsv+'",""'
Get-WFALogger -Info -message $("        [>] Adding conf parameter: " + $wfadocversion)
Add-Content $($wfalocation + "wfa_config.csv") $wfadocversion
$ChangeNumber='"wfa.ChangeNumber.version","'+(Get-ItemProperty "HKLM:\SOFTWARE\NetApp\WFA" |select -ExpandProperty ChangeNumber)+'",""'
Get-WFALogger -Info -message $("        [>] Adding conf parameter: " + $ChangeNumber)
Add-Content $($wfalocation + "wfa_config.csv") $ChangeNumber

if ($wfaversion -ge "4.2.0")
{
	$query="select id,url,bind_username,base_dn from wfa.ldap_server"
	$ldap_server=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
	$ldap_server=$ldap_server[1..($ldap_server[0]+1)]
	$ldap_server | Export-Csv -Path $($wfalocation + "wfa_ldapserver.csv")
}

Get-WFALogger -Info -message $(" [ ] Starting Export of WFA Users !")
$query="select id,name,email,user_role_type,predefined,notifications_enabled,notify_execution_start,notify_execution_end,notify_execution_failed,notify_execution_paused,notify_acquisition_failed,ldap,intro_displayed,checklist_displayed from wfa.user where user_role_type!='System' and ldap=0 order by user_role_type,name"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_users=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_users=$wfa_users[1..($wfa_users[0]+1)]
$wfa_users | Export-Csv -Path $($wfalocation + "wfa_users.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of LDAP Users !")
$query="select * from wfa.ldap_user_group ldapug,wfa.user usr,wfa.ldap_group grp where ldapug.user_id=usr.id and ldapug.ldap_group_id=grp.id"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_ldapusers=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_ldapusers=$wfa_ldapusers[1..($wfa_ldapusers[0]+1)]
$wfa_ldapusers | Export-Csv -Path $($wfalocation + "wfa_ldapusers.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of scheme !")
$query="select wfa.scheme.name,wfa.scheme.pretty_name from wfa.scheme where wfa.scheme.name<>'wfa_internal' order by wfa.scheme.pretty_name"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_scheme=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_scheme=$wfa_scheme[1..($wfa_scheme[0]+1)]
$wfa_scheme | Export-Csv -Path $($wfalocation + "wfa_scheme.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of filter !")
$query="select * from wfa.filter where certification!='NETAPP'"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_filters=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_filters=$wfa_filters[1..($wfa_filters[0]+1)]
$wfa_filters | Export-Csv -Path $($wfalocation + "wfa_filters.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of finder !")
$query="select * from wfa.finder_filter ff,wfa.finder_attribute fa,wfa.finder f,wfa.filter fi,wfa.dictionary_entry de where f.id=ff.finder_id and fa.finder_id=f.id and ff.filter_id=fi.id and f.dictionary_entry_id=de.id and f.certification!='netapp' and f.private_finder='0'"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_finders=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_finders=$wfa_finders[1..($wfa_finders[0]+1)]
$wfa_finders | Export-Csv -Path $($wfalocation + "wfa_finders.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of commands !")
$query="select * from wfa.command_implementation ci,wfa.command_definition cd where ci.command_definition_id=cd.id and certification!='NETAPP' and name!='WFA_Docs'"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_commands=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_commands=$wfa_commands[1..($wfa_commands[0]+1)]
$wfa_commands | Export-Csv -Path $($wfalocation + "wfa_commands.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of workflows !")
$query="select wf.*,wc.position,wc.command_alias,wc.breakpoint_before_command,wc.breakpoint_comment,wc.breakpoint_execution_condition_id from wfa.workflow wf, wfa.workflow_command wc where wf.certification!='NETAPP' and wf.deleted='0' and wf.id=wc.workflow_id and wf.name!='WFA_Docs_Exports' order by wf.id,wc.position"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_workflows=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_workflows=$wfa_workflows[1..($wfa_workflows[0]+1)]
$wfa_workflows | Export-Csv -Path $($wfalocation + "wfa_workflows.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of Categories !")
$query="select * from wfa.category_workflow cwf,wfa.category wc where wc.id=cwf.category_id"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_categories=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_categories=$wfa_categories[1..($wfa_categories[0]+1)]
$wfa_categories | Export-Csv -Path $($wfalocation + "wfa_categories.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of Categories Users!")
$query="select * from wfa.category_user cu,wfa.category wc where wc.id=cu.category_id"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_categorieusers=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_categorieusers=$wfa_categorieusers[1..($wfa_categorieusers[0]+1)]
$wfa_categorieusers | Export-Csv -Path $($wfalocation + "wfa_categorieusers.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of Categories LDAP Groups!")
$query="select * from wfa.category_ldap_group ldpg,wfa.category wc where wc.id=ldpg.category_id"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_categoriegroups=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_categoriegroups=$wfa_categoriegroups[1..($wfa_categoriegroups[0]+1)]
$wfa_categoriegroups | Export-Csv -Path $($wfalocation + "wfa_categoriegroups.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of WFA Packs !")
$query="select name,version,certification,author,description,show_workflows_in_portal from wfa.pack"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_packs=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_packs=$wfa_packs[1..($wfa_packs[0]+1)]
$wfa_packs | Export-Csv -Path $($wfalocation + "wfa_packs.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of WFA functions !")
$query="select * from wfa.function_definition where certification!='NETAPP'"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_functions=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_functions=$wfa_functions[1..($wfa_functions[0]+1)]
$wfa_functions | Export-Csv -Path $($wfalocation + "wfa_functions.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of LDAP Groups !")
$query="select * from wfa.ldap_group"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_ldapgrp=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_ldapgrp=$wfa_ldapgrp[1..($wfa_ldapgrp[0]+1)]
$wfa_ldapgrp | Export-Csv -Path $($wfalocation + "wfa_ldapgrp.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of Schedules !")
$query="select *from wfa.job_schedule_info where type='CronJobSchedule'"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_schedules=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_schedules=$wfa_schedules[1..($wfa_schedules[0]+1)]
$wfa_schedules | Export-Csv -Path $($wfalocation + "wfa_schedules.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of recurring schedules !")
$query="select sa.workflow_name,sa.execution_comment,sa.updated_by,sa.updated_on,jsi.schedule_name from wfa.schedule_association sa,wfa.job_schedule_info jsi where sa.schedule_id=jsi.id"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_recsched=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_recsched=$wfa_recsched[1..($wfa_recsched[0]+1)]
$wfa_recsched | Export-Csv -Path $($wfalocation + "wfa_recsched.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of Data Sources !")
if ($wfaversion -ge "4.2.0")
{
	$query="select ds.name,dsc.ip,dsc.port,dsc.user_name,dsc.timeout_in_minutes,dpt.driver_type,dpt.Product_type,dpt.product_version,dpt.default_port,dpt.method,dpt.type,dpt.script_language,dpt.certification,dpt.version from wfa.data_source ds,wfa.data_source_connection dsc,wfa.data_provider_type dpt where ds.data_source_connection_id=dsc.id and ds.data_provider_type_id=dpt.id"
} else {
	$query="select ds.name,dsc.ip,dsc.port,dsc.user_name,dsc.timeout_in_seconds,dpt.driver_type,dpt.Product_type,dpt.product_version,dpt.default_port,dpt.method,dpt.type,dpt.script_language,dpt.certification,dpt.version from wfa.data_source ds,wfa.data_source_connection dsc,wfa.data_provider_type dpt where ds.data_source_connection_id=dsc.id and ds.data_provider_type_id=dpt.id"
}
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_ds=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_ds=$wfa_ds[1..($wfa_ds[0]+1)]
$wfa_ds | Export-Csv -Path $($wfalocation + "wfa_ds.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of credential !")
$query="select cc.name,cc.ip,cc.user_name,cc.match_type,rst.certification,rst.version,rst.name as 'SystemType',rst.description,rst.connection_protocol from wfa.command_credential cc,wfa.remote_system_type rst where cc.remote_system_type_id=rst.id"
Get-WFALogger -Info -message $("     [Query] " + $query)
$wfa_cred=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$wfa_cred=$wfa_cred[1..($wfa_cred[0]+1)]
$wfa_cred | Export-Csv -Path $($wfalocation + "wfa_cred.csv")


Get-WFALogger -Info -message $(" [ ] Getting playground tables sizes...")
$query="SELECT table_name AS 'Table', round(((data_length + index_length) / 1024 / 1024), 2) 'Size in MB' FROM information_schema.TABLES where table_schema='playground' ORDER BY (data_length + index_length) DESC;"
Get-WFALogger -Info -message $("     [Query] " + $query)
$pgtmpsize=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$pgtmpsize=$pgtmpsize[1..($pgtmpsize[0]+1)]
$NPG_tables=@()
foreach ($entry in $pgtmpsize)
{
	if ($dbg)
	{
		Get-WFALogger -Info -message $("       [>] Found table: '" + $entry.Table + "' with size of '" + $entry.'Size in MB' + " MB")
	}
	$Prop = New-Object PSObject
	$Prop | Add-Member -type NoteProperty -Name 'Table' -Value $entry.Table
	$Prop | Add-Member -type NoteProperty -Name 'Size in MB' -Value $entry.'Size in MB'
	$included=$false
	if ($include_pg_dump)
	{
		if (($entry.'Size in MB' -lt $max_pg_MBdumpsize) -or ($include_pg_large_dump))
		{
			$included=$true
		}
	}
	$Prop | Add-Member -type NoteProperty -Name 'Included' -Value $included
	$Prop | Add-Member -type NoteProperty -Name 'Create Table' -Value "To be defined later"
	$NPG_tables+=$Prop
}
#$NPG_tables | Export-Csv -Path $($wfalocation + "wfa_pgtablesize.csv")

Get-WFALogger -Info -message $(" [ ] Starting Export of playground tables !")
$query="use playground;show tables"
Get-WFALogger -Info -message $("     [Query] " + $query)
$pg_tables=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
$pg_tables=$pg_tables[1..($pg_tables[0]+1)]
foreach ($pg_table in $pg_tables.Tables_in_playground)
{
	$query="SHOW CREATE TABLE playground." + $pg_table + ";"
	Get-WFALogger -Info -message $("        [Query] " + $query)
	$create_table=Invoke-MySqlQuery -Query $query -User $wfadbaccount -Password $wfadbpwd
	$create_table=$create_table[1..($create_table[0]+1)]
	$NPG_tables=$NPG_tables | ForEach-Object { if ($_.Table -eq $create_table.Table) { $_.'Create Table'=$create_table.'Create Table' } $_ }
	if ($include_pg_dump)
	{
		$pg_table_size_inMB=($NPG_tables | where {$_.Table -eq $pg_table}).'Size in MB'
		if (($pg_table_size_inMB -lt $max_pg_MBdumpsize) -or ($include_pg_large_dump))
		{
			$destcsv=$($wfalocation + "wfapgtable_" + $pg_table + ".csv")
			$tmpdest=$($wfalocation + "wfapgtable_" + $pg_table + ".tmp").replace("\","\\")
			if ($dbg)
			{
				Get-WFALogger -Info -message $("           [>] Dumping table: '" + $pg_table +"' content in: '" + $destcsv +"'")
			}
			$tableheader=(Invoke-MySqlQuery -Query ("set session group_concat_max_len = 1000000;select GROUP_CONCAT(CONCAT('"+'"'+"',COLUMN_NAME,'"+'"'+"')) as 'header' from INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '$pg_table' AND TABLE_SCHEMA = 'playground' order BY ORDINAL_POSITION") -User $wfadbaccount -Password $wfadbpwd).header
			Set-Content -Path $destcsv -Value $tableheader
			$getdata="select * from playground." + $pg_table + " INTO OUTFILE '" + $tmpdest + "' FIELDS TERMINATED BY ',' ENCLOSED BY '" + '"' +"' LINES TERMINATED BY '\n';"
			$db_dump=Invoke-MySqlQuery -Query $getdata -User $wfadbaccount -Password $wfadbpwd
			Get-Content $tmpdest | Add-Content -Path $destcsv
			Remove-Item -Path $tmpdest
		} else
		{
			Get-WFALogger -Warn -message $("        [ ] Ignore dump of table: '" + $pg_table +"' rather because the table size in MB: " + $pg_table_size_inMB.ToString() + " is > than " + $max_pg_MBdumpsize.ToString() + " or because include_pg_large_dump=" + $include_pg_large_dump)
		}
	} else
	{
		Get-WFALogger -Warn -message $("           [>>>] Ignore dump of table: '" + $pg_table +"' due to include_pg_dump=" + $include_pg_dump)
	}
}
$NPG_tables | Export-Csv -Path $($wfalocation + "wfa_pgtables.csv")

Add-Type -Assembly "System.IO.Compression.FileSystem"
[System.IO.Compression.ZipFile]::CreateFromDirectory($wfalocation, $ZipFile)
Remove-Item $wfalocation -Recurse
Get-WFALogger -Warn -message $("Now it's time to use the zip result file (located  in " + $ZipFile + ") as an input for the WFADocs script." )
