# This script can be used to generate some AzureAD users which will be assigned with high privileges.
# In addition, it creates new AzureAD Apps and registers Service Principals which will be assigned with 
# high Graph API permissions and / or high Azure AD roles for privesc attack paths

# Number of Azure AD users you want to create
[int]$usercount = 10
# File for generated users and their passwords
[string]$UserlistJSON = ".\AzureAD-users.json"
# File for generated apps and service principals with the MS Graph permission assigned
[string]$SPlistJSON = ".\AzureAD-svcprincipals.json"
# Define list of dangerous MS graph permissions we want to assign
[array]$CSVHeader = @("Id","Permission")
[array]$DangerousGraphPermissionsList = @("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8,RoleManagement.ReadWrite.Directory","06b708a9-e830-4db3-a914-8e69da51d44f,AppRoleAssignment.ReadWrite.All")
[array]$DangerousGraphPermissions = $DangerousGraphPermissionsList | ConvertFrom-Csv -Header $CSVHeader
[array]$PotentialSPAbuseGraphPermissionList = @("1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9,Application.ReadWrite.All")
[array]$PotentialSPAbuseGraphPermissions = $PotentialSPAbuseGraphPermissionList | ConvertFrom-Csv -Header $CSVHeader
# Define dangerous Azure AD roles
[array]$MostDangerousAzADRBACRoles = @("Global Administrator","Privileged Role Administrator","Privileged Authentication Administrator","Partner Tier2 Support")
[array]$PotentiallyDangerousAzADRBACRoles = @("Application Administrator","Authentication Administrator","Azure AD joined device local administrator","Cloud Application Administrator","Cloud device Administrator","Exchange Administrator","Groups Administrator","Helpdesk Administrator","Hybrid Identity Administrator","Intune Administrator","Password Administrator","User Administrator","Directory Writers")

Write-Host "Script started on $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"

# Import module AzureAD
Try {
    Write-Host "Importing module AzureAD..."
    Import-Module AzureAD -ErrorAction Stop
}
Catch {
    Write-Warning "Could not import module AzureAD, which is required. Error message:`r`n$($error[0].Exception)`r`nTerminating script..."
    Exit
}
# Import module Az
Try {
    Write-Host "Importing modules Az.Accounts,Az.Resources,Az.Websites..."
    Import-Module Az.Accounts,Az.Resources,Az.Websites -ErrorAction Stop
}
Catch {
    Write-Warning "Could not import module Az, which is required. Error message:`r`n$($error[0].Exception)`r`nTerminating script..."
    Exit
}

# ask for tenant domain
$tenantDomain = Read-Host "Please provide the domain of the target tenant"
# Connect to the tenant
Write-Host "Connecting to the Azure tenant now, please login with a Global Admin"
$ConnectAzADAcc = Connect-AzureAD -TenantDomain $tenantDomain
if($ConnectAzADAcc.TenantDomain -ne $tenantDomain){
    # something went wrong...
    Write-Warning "Something went wrong when connecting to the Azure tenant. It was not possible to check the connection context. Script will abort..."
    Exit
}else{
    Write-host "Connected to tenant $($ConnectAzADAcc.Context.Tenant.Id)"
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
            UserRole = @()
            UserMSGraphAppRole = "N/A"
        }
        $UserExport += $data
    }catch{
        Write-Host "Could not create Azure AD user. Error message:`r`n$($error[0].Exception)`r`nTerminating script..."
        Exit
    }
}

# Get all the AAD roles and role templates into array
$AzureADRoles = Get-AzureADDirectoryRole
$AzureADRoleTemplates = Get-AzureADDirectoryRoleTemplate

# Combine the dangerous roles we want to assign
$RolesToAssign = $PotentiallyDangerousAzADRBACRoles + $MostDangerousAzADRBACRoles

# Make sure every defined dangerous role is assigned to any user
foreach($AADrole in $RolesToAssign){
    # choose a created user at random to assign the role
    $AssignUser = $UserExport | Get-Random
    try{
        $UserObjectId = (Get-AzureADUser -SearchString "$($AssignUser.UserUPN)" | select -ExpandProperty ObjectId)
        $AADRoleTemplId = ($AzureADRoleTemplates | Where-Object { $_.DisplayName -like $AADRole} | select -ExpandProperty ObjectId)
        # First make sure the role is enabled
        $CheckRole = ($AzureADRoles | Where-Object { $_.DisplayName -like "$AADRole"})
        if(($CheckRole.count -lt 1) -or ($CheckRole.RoleDisabled -eq $true)){
            Enable-AzureADDirectoryRole -RoleTemplateId $AADRoleTemplId
        }
        # Now get the RoleId and assign it
        $AADRoleId = (Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -like "$AADrole"} | select -ExpandProperty ObjectId)
        Add-AzureADDirectoryRoleMember -ObjectId $AADRoleId -RefObjectId $UserObjectId
        ($UserExport |Where-Object { $_.UserUPN -like "$($AssignUser.UserUPN)"}).UserRole += "$AADRole"
    }catch{
        Write-Warning "Could not assign the role $AADRole to user $($AssignUser.UserUPN)! Errormessage:`r`n$($error[0].Exception)`r`n"
    }
}

# MS Graph App Id (This is always the same!)
$GraphAppId = "00000003-0000-0000-c000-000000000000"
# Get the Graph SP
$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"
$SPExport = @()
# Make sure the dangerous Graph permissions ($DangerousGraphPermissions) are assigned
foreach($GraphPermission in $DangerousGraphPermissions){
    $PermissionName = $GraphPermission.Permission
    # Create new AzureAD app
    $AzureADApp = New-AzureADApplication -DisplayName "TestApp_dvaad_$PermissionName"
    # Generate service principal for the app
    $AzureADAppSP = New-AzureADServicePrincipal -AppId $AzureADApp.AppId
    # Get the Graph Permission (app role) and assign it to the new SP
    $AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
    New-AzureAdServiceAppRoleAssignment -ObjectId $AzureADAppSP.ObjectId -PrincipalId $AzureADAppSP.ObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $AppRole.Id
    $data = [PSCustomObject]@{
        AppName = $($AzureADApp.DisplayName)
        SvcPrincipalId = $($AzureADAppSP.ObjectId)
        GraphPermission = $PermissionName
        AzureADPermission = "N/A"
    }
    $SPExport += $data
}

# Assign the potentially dangerous Graph permissions ($PotentialSPAbuseGraphPermissions) to users, so that there is a privesc path
foreach($GraphPermission in $PotentialSPAbuseGraphPermissions){
    $PermissionName = $GraphPermission.Permission
    # Get the user defined graph app role
    $AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
    # Assign the graph app role to a user (which is not already assigned one of the higher Azure AD roles) 
    $ChosenUser = $Userexport |Where-Object { $_ -notin ($Userexport |Where-Object { $_.UserRole -match "\b($($MostDangerousAzADRBACRoles -join '|'))\b"})} | Select-Object -First 1
    $UserToAssign = Get-AzureADUser -SearchString "$($ChosenUser.UserUPN)"
    New-AzureADUserAppRoleAssignment -ObjectId $UserToAssign.ObjectId -PrincipalId $UserToAssign.ObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $($GraphPermission.id)
    $UserExport | Where-Object { $_.UserUPN -like $UserToAssign.UserPrincipalName } | % { $_.UserMSGraphAppRole = "$PermissionName"}
}

# Connect to the tenant using Az module
Write-Host "Connecting to the Azure tenant with the Az module now, please login with a Global Admin"
$AzTenantId = (Get-AzureADTenantDetail).ObjectId
$ConnectAzAcc = Connect-AzAccount -Tenant $AzTenantId
# get subscriptions and ask for which one to use
$AzSubs = Get-AzSubscription
if($AzSubs.count -lt 1){
    Write-Warning "No subscription was identified in this environment, cannot continue! Please create a subscription first and ensure you have access to it."
    Exit
}
Write-host "The following subscriptions are available to the provided credentials:`r`n$AzSubs`r`n"
$continue = $false
do{
    $AzSubIdChosen = Read-Host "Please insert the SubscriptionId for which you want to deploy the vulnerable apps"
    try{
        Set-AzContext -Subscription $AzSubIdChosen -ErrorAction Stop
        $continue = $true
    }catch{
        Write-Host "Something went wrong... Try again."
    }
}while($continue -eq $false)
Write-host "Collecting location information..."
$AzLocations = Get-AzLocation
Write-host "$($AzLocations.DisplayName -join "`r`n")"
$ChosenLocation = Read-Host "Please choose which location from the list above you want to deploy the new resources to"

########## Deploy Web App whose Managed Identity has Privileged Role Administrator Role ##########
# Create new Resource Group with Az Web App
Write-Host "Creating Resource Group..."
$NewAzRG = New-AzResourceGroup -Name "RG_dvaad_$(((New-Guid) -split("-"))[0])" -Location "$ChosenLocation"
# Create App Service Plan
Write-Host "Creating App Service Plan..."
$NewAzAppSvcPlan = New-AzAppServicePlan -ResourceGroupName "$($NewAzRG.ResourceGroupName)" -Name "dvaad_AppSvcPlan_$(((New-Guid) -split("-"))[0])" -Location "$ChosenLocation" -Tier "Free"
# Create App Service
Write-Host "Creating App Service..."
$NewAzAppSvc = New-AzWebApp -ResourceGroupName "$($NewAzRG.ResourceGroupName)" -Name "dvaad-AppSvc-$(((New-Guid) -split("-"))[0])" -Location "$ChosenLocation" -AppServicePlan "$($NewAzAppSvcPlan.Name)"
# Assign Managed Identity to web service
Write-Host "Assigning Managed Identity to web app..."
Set-AzWebApp -AssignIdentity $true -Name $($NewAzAppSvc.Name) -ResourceGroupName "$($NewAzRG.ResourceGroupName)"
# Get the assigned identity
$NewAzAppSvcPrincipalId = (Get-AzWebApp -Name $NewAzAppSvc.Name).Identity.PrincipalId
# Collecting Role information in AD and assigning role to managed identity...
$AzureADRoleDefs = Get-AzureADMSRoleDefinition
$AzADPrivRoleAdminRole = $AzureADRoleDefs | Where-Object { $_.DisplayName -like "Privileged Role Administrator"}
New-AzureADMSRoleAssignment -RoleDefinitionId $($AzADPrivRoleAdminRole.Id) -PrincipalId $NewAzAppSvcPrincipalId -DirectoryScopeId '/'

# Add new user and assign with contributor rights to the new resource group
$UserUPN = "dvaad-rgcontributor@$tenantDomain"
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PWString = [System.Web.Security.Membership]::GeneratePassword(14,1)
$PasswordProfile.Password = $PWString
$NewAzUser = New-AzureADUser -AccountEnabled $true -DisplayName "dvaad rgcontributor" -UserPrincipalName $UserUPN -PasswordProfile $PasswordProfile -MailNickName "dvaadrgcontributor"
New-AzRoleAssignment -ObjectId $($NewAzUser.ObjectId) -RoleDefinitionName "Contributor" -ResourceGroupName "$($NewAzRG.ResourceGroupName)"
# add created user to export data
$data = [PSCustomObject]@{
    UserUPN = $UserUPN
    UserPW = $PWString
    UserRole = @("Contributor")
}
$UserExport += $data
# add created app and service principal to export data
$data = [PSCustomObject]@{
    AppName = $($NewAzAppSvc.Name)
    SvcPrincipalId = $NewAzAppSvcPrincipalId
    GraphPermission = "N/A"
    AzureADPermission = "Privileged Role Administrator"
}
$SPExport += $data

# Export created users with passwords and roles
$UserExport | ConvertTo-Json | Set-Content -Path $UserlistJSON
# Export created Apps and SPs
$SPExport | ConvertTo-Json | Set-Content -Path $SPlistJSON

#### DONE ####
Write-Host "Users created in Azure AD, UPN and PWs exported to $UserlistJSON"
Write-Host "Apps and Service Principals created in Azure AD, details exported to $SPlistJSON"
Write-Host "Script finished on $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"