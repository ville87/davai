# This script can be used to generate some AzureAD users which will be assigned with high privileges.
# In addition, it creates new AzureAD Apps and registers Service Principals which will be assigned with high Graph API permissions

# Number of Azure AD users you want to create
[int]$usercount = 10
# File for generated users and their passwords
[string]$UserlistCSV = ".\AzureAD-users.csv"
# File for generated apps and service principals with the MS Graph permission assigned
[string]$SPlistCSV = ".\AzureAD-svcprincipals.csv"
# Define list of dangerous MS graph permissions we want to assign
[array]$CSVHeader = @("Id","Permission")
[array]$DangerousGraphPermissionsList = @("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8,RoleManagement.ReadWrite.Directory","06b708a9-e830-4db3-a914-8e69da51d44f,AppRoleAssignment.ReadWrite.All")
[array]$DangerousGraphPermissions = $DangerousGraphPermissionsList | ConvertFrom-Csv -Header $CSVHeader
# Define dangerous Azure AD roles
[array]$MostDangerousAzADRBACRoles = @("Global Administrator","Privileged Role Administrator","Privileged Authentication Administrator","Partner Tier2 Support")
[array]$PotentiallyDangerousAzADRBACRoles = @("Application Administrator","Authentication Administrator","Azure AD joined device local administrator","Cloud Application Administrator","Cloud device Administrator","Exchange Administrator","Groups Administrator","Helpdesk Administrator","Hybrid Identity Administrator","Intune Administrator","Password Administrator","User Administrator","Directory Writers")

# Import module AzureAD
Try {
    Import-Module AzureAD -ErrorAction Stop
}
Catch {
    Write-Warning "Could not import module AzureAD, which is required. Error message:`r`n$($error[0].Exception)`r`nTerminating script..."
    Exit
}
# ask for tenant domain
$tenantDomain = Read-Host "Please provide the domain of the target tenant"
# Connect to the tenant
Write-Host "Connecting to the Azure tenant now, please login with a Global Admin"
$ConnectAzAcc = Connect-AzureAD -TenantDomain $tenantDomain
if($ConnectAzAcc.TenantDomain -ne $tenantDomain){
    # something went wrong...
    Write-Warning "Something went wrong when connecting to the Azure tenant. It was not possible to check the connection context. Script will abort..."
    Exit
}else{
    Write-host "Connected to tenant $($ConnectAzAcc.Context.Tenant.Id)"
}
# Check that current user is global admin
if((Get-AzureADDirectoryRole).DisplayName -notcontains "Global Administrator"){
    Write-Warning "You are not logged in as a Global Admin. Please restart the script and login with a Global Admin. Script will abort..."
    Exit
}

# generate Azure AD users
$userlist = @()
for($i=1;$i -le $usercount;$i++){
    $response = Invoke-RestMethod -Uri "https://randomuser.me/api/" -UseBasicParsing -Method Get
    $name = ($response.results.email -split ("@"))[0]
    $userlist += $name
}

# Add required type for pw generator
Add-Type -AssemblyName 'System.Web'
$UserExport = @()
# Create the users in AzureAD
foreach($userentry in $userlist){
    try{
        $UserUPN = "$userentry@$tenantDomain"
        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
        # generate random password with length of 14 and minimum of 1 alphanumeric
        $PWString = [System.Web.Security.Membership]::GeneratePassword(14,1)
        $PasswordProfile.Password = $PWString
        New-AzureADUser -AccountEnabled $true -DisplayName "$($userentry.split(".")[0]) $($userentry.split(".")[1])" -UserPrincipalName $UserUPN -PasswordProfile $PasswordProfile -MailNickName "$($userentry[0])$($userentry.split(".")[1])"
        $data = [PSCustomObject]@{
            UserUPN = $UserUPN
            UserPW = $PWString
        }
        $UserExport += $data
    }catch{
        Write-Host "Could not create Azure AD user. Error message:`r`n$($error[0].Exception)`r`nTerminating script..."
        Exit
    }
}
# Export created users with passwords
$UserExport | Export-Csv -NoTypeInformation -Path $UserlistCSV

# Get all the AAD roles into array
$AzureADRoles = Get-AzureADDirectoryRoleTemplate

# Combine the dangerous roles we want to assign
$RolesToAssign = $PotentiallyDangerousAzADRBACRoles + $MostDangerousAzADRBACRoles

# Make sure every defined dangerous role is assigned to any user
foreach($AADrole in $RolesToAssign){
    # choose a created user at random to assign the role
    $AssignUser = $UserExport | Get-Random
    try{
        $UserObjectId = (Get-AzureADUser -SearchString "$($AssignUser.UserUPN)" | select -ExpandProperty ObjectId)
        $AADRoleTemplId = ($AzureADRoles | Where-Object { $_.DisplayName -like $AADRole} | select -ExpandProperty ObjectId)
        # First make sure the role is enabled
        Enable-AzureADDirectoryRole -RoleTemplateId $AADRoleTemplId
        # Now get the RoleId and assign it
        $AADRoleId = (Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -like "$AADrole"} | select -ExpandProperty ObjectId)
        Add-AzureADDirectoryRoleMember -ObjectId $AADRoleId -RefObjectId $UserObjectId
    }catch{
        Write-Warning "Could not assign the role $AADRole to user $($AssignUser.UserUPN)! Errormessage:`r`n$($error[0].Exception)`r`n"
    }
}

# MS Graph App Id (This is always the same!)
$GraphAppId = "00000003-0000-0000-c000-000000000000"
# Get the Graph SP
$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"
# Get the graph appid
$graphobjid  = (Get-AzureADServicePrincipal -All $true | Where-Object { $_.AppId -eq $GraphAppId } |select -ExpandProperty ObjectId)
$SPExport = @()
# Make sure the Graph permissions are assigned
foreach($GraphPermission in $DangerousGraphPermissions){
    $PermissionName = $GraphPermission.Permission
    # Get the user defined graph app role
    $AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
    # Create new AzureAD app
    $AzureADApp = New-AzureADApplication -DisplayName "TestApp_$PermissionName"
    # Generate service principal for the app
    $AzureADAppSP = New-AzureADServicePrincipal -AppId $AzureADApp.AppId
    # Get the Graph Permission (app role) and assign it to the new SP
    $AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
    New-AzureAdServiceAppRoleAssignment -ObjectId $AzureADAppSP.ObjectId -PrincipalId $AzureADAppSP.ObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $AppRole.Id
    $data = [PSCustomObject]@{
        AppName = $($AzureADApp.DisplayName)
        SvcPrincipalId = $($AzureADAppSP.ObjectId)
        GraphPermission = $PermissionName
    }
    $SPExport += $data
}
# Export created Apps and SPs
$SPExport | Export-Csv -NoTypeInformation -Path $SPlistCSV

#### DONE ####
Write-Host "Script done!"
Write-Host "Users created in Azure AD, UPN and PWs exported to $UserlistCSV"
Write-Host "Apps and Service Principals created in Azure AD, details exported to $SPlistCSV"
