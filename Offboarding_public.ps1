#Input your Sharepoint admin URL in the single quotes below
$SP_URL = ''

#Offboarding V2
$highlightcolor = "Green"
#Loop forever
while($true)
{

#use existing session or reconnect to online services
$reconn =  Read-Host "Do you need to reconnect to online services as admin?"
if ($reconn -eq 'y') {
   #Connect to online services
Connect-AzureAD -Credential $credentials #AzureAD 
Connect-SPOService -Url $SP_URL -credential $credentials  #sharepointOnline
Connect-EXOPSSession -credential $credentials #excahnge
Connect-PnPOnline -Url $SP_URL -UseWebLogin   #Onedrive
Connect-MsolService -Credential $credentials #MSonline
}  

#Start at local AD
import-module activedirectory
set-location ad:

#initialize variables to prevent accidental movements
$user = ''
$Username = ''
$dn = ''
$ADgroups = ''
$azureADuser = ''
$manager  = ''
$mailbox = ''
$OneDriveUrl = ''
$Office365GroupsMember = ''
$grp = ''
$members = ''
$NewMemberGroups = ''


#Set variables for distinguished name, SAM account name
$Username = Read-Host -Prompt 'Input the user email address'
$user = (Get-ADUser -Filter {UserPrincipalName -eq $username}).SAMAccountName
#$user = $user.SAMAccountName
$dn = (get-aduser -id $user).distinguishedname


$ADgroups = Get-ADPrincipalGroupMembership -Identity $user | where {$_.Name -ne "Domain Users"}
"$username is a member of the following groups currently:"
$adgroups.name
Remove-ADPrincipalGroupMembership -Identity "$user" -MemberOf $ADgroups


Disable-ADAccount -Identity $User
#the line below has been anonymized
$moveToOU = "OU=Disabled_SharedMailboxes,OU=Locations,OU=Redacted,DC=redacted,DC=local"
Move-ADObject -Identity $dn -TargetPath $moveToOU

#set variables
try { $AzureADUser = Get-AzureADUser -ObjectId $Username }
catch { 'Request_ResourceNotFound' } 
#if ($azureADuser -ne '') {
$Mailbox = Get-Mailbox | Where {$_.PrimarySmtpAddress -eq $username}
$Manager = Get-AzureADUserManager -ObjectId $AzureADUser.ObjectId
#    if (!$manager) {   
#        $manager = Read-Host -Prompt 'No manager set in AD.`nPlese type email of manager to set' }
#Not needed?   $ManagerUPN = Get-AzureADUser -ObjectId $Manager

#Disable Account
Set-AzureADUser -ObjectId $AzureADUser.ObjectId -AccountEnabled $false

#revoke Active Sessions
Revoke-SPOUserSession -User $Username -confirm:$False

#Conver Mailbox to shared
Set-Mailbox $Username -Type Shared
Add-MailboxPermission -Identity $AzureADUser.Displayname -User $manager.DisplayName -AccessRights FullAccess

#Cancel all events upto 1820 days into future
Remove-CalendarEvents -Identity $Mailbox.Alias -QueryWindowInDays 1820 -CancelOrganizedMeetings -confirm:$False

#OneDrive
$OneDriveUrl = Get-PnPUserProfileProperty -Account $username | select PersonalUrl
Set-SPOUser $Manager.UserPrincipalName -Site $OneDriveUrl.PersonalUrl -IsSiteCollectionAdmin:$true

#Remove from Office 365 Groups
$Office365GroupsMember = Get-UnifiedGroup | where { (Get-UnifiedGroupLinks $_.Alias -LinkType Members | foreach {$_.name}) -contains $mailbox.Alias}
$NewMemberGroups = @()
foreach($GRP in $Office365GroupsMember)
	{
	$Members = Get-UnifiedGroupLinks $GRP.Alias -LinkType Members
	if ($Members.Count -le 1)
		{
		#Our user is the only Member
		Add-UnifiedGroupLinks -Identity $GRP.Alias -LinkType Members -Links $Manager.UserPrincipalName
		$NewMemberGroups += $GRP
		Remove-UnifiedGroupLinks -Identity $GRP.Alias -LinkType Members -Links $Username -Confirm:$false
		}
	else
		{
		#There Are Other Members
		Remove-UnifiedGroupLinks -Identity $GRP.Alias -LinkType Members -Links $Username -Confirm:$false
		}
	}

#remove all licenses from account
(get-MsolUser -UserPrincipalName $Username).licenses.AccountSkuId |
foreach{
    Set-MsolUserLicense -UserPrincipalName $Username -RemoveLicenses $_
}

#Verify All Changes
#Verify Enabled Status
"$user offboarding report below"
"------------------------------"
Write-Host "AD sign in allowed?:" + (get-ADuser $user).Enabled -BackgroundColor $highlightcolor
"Is Office365/Azure sign in allowed?: "+(Get-AzureADUser -ObjectId $username).AccountEnabled
#Check to see location in active directory
"On-Prem AD OU: "+(get-aduser -id $user).distinguishedname
#Get all Group memberships (should only be Domain Users)
"$user is a member of the following groups:`n"+(Get-ADPrincipalGroupMembership -Identity $user).samaccountname
#get licenses
"$user has the following office 365 Licenses:`n"+(get-MsolUser -UserPrincipalName $Username).licenses.AccountSkuId
}
