# DVAAD
Damn Vulnerable Azure AD   
> :warning: **This script should not be used in production environments!**

## Description
This script generates a number of AzureAD accounts and assigns them with high privileges.
In addition, it registers Azure AD apps and service principals, which it assigns with high MS Graph API permissions and Azure AD permissions for Privilege Escalation paths.

## Created Objects and Attack Paths
- Creates a number of Azure AD users (default: 10, can be changed in script)
- Assigns the users with randomly generated passwords
- Assigns the users randomly with the following Azure AD Roles:
    - `Global Administrator`
    - `Privileged Role Administrator`
    - `Privileged Authentication Administrator`
    - `Partner Tier2 Support`
    - `Application Administrator`
    - `Authentication Administrator`
    - `Azure AD joined device local administrator`
    - `Cloud Application Administrator`
    - `Cloud device Administrator`
    - `Exchange Administrator`
    - `Groups Administrator`
    - `Helpdesk Administrator`
    - `Hybrid Identity Administrator`
    - `Intune Administrator`
    - `Password Administrator`
    - `User Administrator`
    - `Directory Writers`
- Assigns a user with the MS Graph App role `Application.ReadWrite.All` which would allow for privilege escalation if an app has high privileges
- Creates two new AzureAD apps (TestApp_dvaad_$PermissionName) and assigns the Graph API roles `RoleManagement.ReadWrite.Directory`,`AppRoleAssignment.ReadWrite.All`
- Creates a new resource group (RG_dvaad_xxxxxxxx)
- Creates a new Azure Web App Service (dvaad-AppSvc-xxxxxxxx) in this RG and assigns it with a managed identity. This managed identity is assigned with the Azure AD role 
    `Privileged Role Administrator`
- Creates a new user (dvaad-rgcontributor@$tenantDomain) and assigns it with the `Contributor` RBAC role on the new resource group