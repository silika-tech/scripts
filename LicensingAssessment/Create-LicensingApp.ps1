param(
    [string]$AppDisplayName = 'Silika Licensing Assessment',
    [switch]$IncludeExchangeAppAccess = $true,
    [int]$SecretValidityYears = 1
)

# Ensure TLS 1.2 is used (required for Microsoft Graph API)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure the required Microsoft Graph modules are installed
Write-Host "Checking and installing required Microsoft Graph modules..." -ForegroundColor Cyan
$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Reports'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing module: $module" -ForegroundColor Yellow
        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
    } else {
        Write-Host "Module $module is already installed." -ForegroundColor Green
    }
    Import-Module $module -Force
}

# Connect to Microsoft Graph with necessary permissions to create the licensing application and disable report concealing
Write-Host "Connecting to Microsoft Graph API. Please sign in when prompted..." -ForegroundColor Cyan
try {
    Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'ReportSettings.ReadWrite.All' -ErrorAction Stop
    Write-Host 'Successfully connected to Microsoft Graph.' -ForegroundColor Green
} catch {
    Write-Host 'Error: Failed to connect to Microsoft Graph.' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Verify connection
$context = Get-MgContext
if (-not $context) {
    Write-Host 'Error: Not connected to Microsoft Graph. Please try again.' -ForegroundColor Red
    exit 1
}
Write-Host "Connected as: $($context.Account)" -ForegroundColor Cyan

try {
    Write-Host 'Checking Microsoft 365 report concealment setting...' -ForegroundColor Cyan
    $reportSettings = Get-MgAdminReportSetting -ErrorAction Stop
    if ($reportSettings.DisplayConcealedNames -eq $false) {
        Write-Host 'Report identifiable names are already enabled.' -ForegroundColor Green
    } else {
        $params = @{
            displayConcealedNames = $false
        }

        Update-MgAdminReportSetting -BodyParameter $params -ErrorAction Stop | Out-Null
        Write-Host 'Enabled identifiable names in Microsoft 365 usage reports.' -ForegroundColor Green
    }
} catch {
    Write-Host "[WARNING] Failed to update admin report settings: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host '[WARNING] Usage reports may remain anonymized until displayConcealedNames is set to true.' -ForegroundColor Yellow
}

# Create the App registration
Write-Host "Creating $AppDisplayName App Registration in Microsoft Entra ID..." -ForegroundColor Cyan
try {
    $app = New-MgApplication -DisplayName $AppDisplayName -ErrorAction Stop
    Write-Host 'App Registration created successfully.' -ForegroundColor Green
} catch {
    Write-Host 'Error: Failed to create App Registration.' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    if ($_.Exception.InnerException) {
        Write-Host "Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    exit 1
}

# Create a service principal for the app
Write-Host 'Creating Service Principal for the App Registration...' -ForegroundColor Cyan
try {
    $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
    Write-Host 'Service Principal created successfully.' -ForegroundColor Green
} catch {
    Write-Host 'Error: Failed to create Service Principal.' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

function Grant-AppPermission {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId,
        [Parameter(Mandatory = $true)]
        $ResourceServicePrincipal,
        [Parameter(Mandatory = $true)]
        [string]$PermissionValue
    )

    $role = $ResourceServicePrincipal.AppRoles | Where-Object {
        $_.Value -eq $PermissionValue -and $_.AllowedMemberTypes -contains 'Application'
    } | Select-Object -First 1

    if (-not $role) {
        Write-Host "[WARNING] Permission '$PermissionValue' not found on resource '$($ResourceServicePrincipal.DisplayName)'. Skipping..." -ForegroundColor Yellow
        return $false
    }

    try {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -ResourceId $ResourceServicePrincipal.Id -AppRoleId $role.Id -PrincipalId $ServicePrincipalId -ErrorAction Stop | Out-Null
        Write-Host "Assigned permission: $PermissionValue" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[ERROR] Failed to assign permission '$PermissionValue': $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-OrActivateDirectoryRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $role = Get-MgDirectoryRole -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($role) {
        return $role
    }

    $template = Get-MgDirectoryRoleTemplate -All -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $DisplayName } | Select-Object -First 1
    if (-not $template) {
        Write-Host "[WARNING] Could not find directory role template for '$DisplayName'." -ForegroundColor Yellow
        return $null
    }

    try {
        $null = New-MgDirectoryRole -RoleTemplateId $template.Id -ErrorAction Stop
    } catch {
        Write-Host "[WARNING] Failed to activate directory role '$DisplayName': $($_.Exception.Message)" -ForegroundColor Yellow
    }

    return Get-MgDirectoryRole -Filter "displayName eq '$DisplayName'" -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Add-ServicePrincipalToDirectoryRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId,
        [Parameter(Mandatory = $true)]
        [string]$RoleDisplayName
    )

    $role = Get-OrActivateDirectoryRole -DisplayName $RoleDisplayName
    if (-not $role) {
        return $false
    }

    try {
        $existingMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
        $alreadyAssigned = @($existingMembers | Where-Object { $_.Id -eq $ServicePrincipalId }).Count -gt 0
        if ($alreadyAssigned) {
            Write-Host "Directory role already assigned: $RoleDisplayName" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "[WARNING] Could not verify existing '$RoleDisplayName' assignments: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    try {
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -BodyParameter @{
            '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$ServicePrincipalId"
        } -ErrorAction Stop | Out-Null
        Write-Host "Assigned directory role: $RoleDisplayName" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[ERROR] Failed to assign directory role '$RoleDisplayName': $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Define required permissions for the App Registration (API permissions for Microsoft Graph)
Write-Host 'Defining required API permissions for Microsoft Graph...' -ForegroundColor Cyan
$graphPermissions = @(
    'User.Read.All',
    'AuditLog.Read.All',
    'Reports.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'Organization.Read.All',
    'TeamsUserConfiguration.Read.All'
)

# Retrieve Microsoft Graph service principal
Write-Host 'Retrieving Microsoft Graph Service Principal...' -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop
if (-not $graphSp) {
    Write-Host 'Error: Failed to retrieve Microsoft Graph Service Principal. Ensure you have required permissions.' -ForegroundColor Red
    exit 1
}

# Assign Graph permissions
Write-Host 'Assigning Graph API permissions to the App Registration...' -ForegroundColor Cyan
foreach ($permission in $graphPermissions) {
    $null = Grant-AppPermission -ServicePrincipalId $sp.Id -ResourceServicePrincipal $graphSp -PermissionValue $permission
}

# Optional Exchange app-only permission (used for identifying litigation hold and archive usage)
if ($IncludeExchangeAppAccess) {
    Write-Host 'IncludeExchangeAppAccess enabled - assigning Exchange.ManageAsApp...' -ForegroundColor Cyan
    try {
        $exchangeOnlineSp = Get-MgServicePrincipal -Filter "appId eq '00000002-0000-0ff1-ce00-000000000000'" -ErrorAction Stop
        if ($exchangeOnlineSp) {
            $null = Grant-AppPermission -ServicePrincipalId $sp.Id -ResourceServicePrincipal $exchangeOnlineSp -PermissionValue 'Exchange.ManageAsApp'
        } else {
            Write-Host '[WARNING] Could not resolve Exchange Online service principal. Skipping Exchange.ManageAsApp.' -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[WARNING] Failed to assign Exchange.ManageAsApp: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Assign directory roles to service principal. Exchange app-only PowerShell requires
# Exchange.ManageAsApp plus an Entra role that maps into Exchange RBAC; Global
# Reader maps to View-Only Organization Management for read-only collection.
Write-Host 'Assigning Global Reader directory role to the service principal...' -ForegroundColor Cyan
$null = Add-ServicePrincipalToDirectoryRole -ServicePrincipalId $sp.Id -RoleDisplayName 'Global Reader'

if ($IncludeExchangeAppAccess) {
    Write-Host '[INFO] Exchange app-only RBAC changes can take 30 minutes to 2 hours to become effective.' -ForegroundColor Yellow
}

# Create a client secret for the app
Write-Host 'Creating Application Secret...' -ForegroundColor Cyan
$passwordCred = @{
    DisplayName = "$AppDisplayName Secret"
    EndDateTime = (Get-Date).AddYears($SecretValidityYears)
}

try {
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $passwordCred -ErrorAction Stop
    Write-Host 'Application Secret created successfully.' -ForegroundColor Green
} catch {
    Write-Host 'Error: Failed to create Application Secret.' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Output results
$clientId = $app.AppId
$tenantId = $context.TenantId
$secretValue = $secret.SecretText

Write-Host '----------------------------------------' -ForegroundColor Cyan
Write-Host 'App Registration Completed Successfully' -ForegroundColor Green
Write-Host "App Display Name: $AppDisplayName" -ForegroundColor White
Write-Host "Client ID: $clientId" -ForegroundColor White
Write-Host "Tenant ID: $tenantId" -ForegroundColor White
Write-Host "Secret Value: $secretValue" -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor Cyan
