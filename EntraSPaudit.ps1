#############################################################################################################################################
# EntraSPaudit.ps1                                                                                                                          #
#                                                                                                                                           # 
# BEFORE EXECUTING THE SCRIPT:                                                                                                              #
#                                                                                                                                           # 
# 1) Create an Azure AD App registration in Entra ID with required API permissions (Admin consented)                                        #  
#    - MS Graph permissions: Application.Read.All, AuditLog.Read.All, Directory.Read.All, User.Read.All, ServicePrincipalEndpoint.Read.All  #
# 2) Create a short-lived client secret for the APP registration (copy the secret value before closing the blade)                           #
# 3) Set the following environment variables in your PowerShell session:                                                                    #
#                                                                                                                                           #
# $env:MG_TENANTID = "<YOUR-TENANT-ID>"                                                                                                     #
# $env:MG_CLIENTID = "<YOUR-CLIENT-ID>"                                                                                                     #
# $env:MG_CLIENTSECRET = "<YOUR-CLIENTSECRET>"                                                                                              #
#                                                                                                                                           # 
# TO EXECUTE THE SCRIPT:                                                                                                                    #
#                                                                                                                                           # 
# pwsh -File .\EntraSPaudit.ps1                                                                                                             #
#                                                                                                                                           #
# OUTPUT : .\Entra_Service_Principal_Audit\Entra_Service_Principal_Audit_YYYY-MM-DD_HHMMhs.csv                                              #
#                                                                                                                                           # 
#############################################################################################################################################
# Purpose: Audit Entra ID Service Principals and export a detailed CSV summary                                                              #
#############################################################################################################################################
# Connects to Microsoft Graph using app-only credentials from environment variables
# Reads recent sign-in logs to correlate activity with Service Principals
# Queries Service Principals tagged integrated applications for tenant visibility
# Collects SP properties, credentials, app roles, owners, endpoints, and additional metadata
# Resolves associated App Registrations for keys, secrets, and federated credentials
# Computes credential status: CURRENT, SOON, or EXPIRED based on expiry windows
# Flattens credentials into fixed CSV columns for consistent reporting and automation
# Outputs a timestamped CSV suitable for SIEM ingestion or remediation workflows
# Advantage: Centralized inventory to detect unused, orphaned, or risky Service Principals
# Advantage: Identifies expiring or expired credentials to prevent authentication outages
# Advantage: Exposes owners and notification addresses for rapid remediation contact
# Advantage: Correlates sign-in counts to prioritize cleanup of dormant principals
# Advantage: Shows federated credentials to audit external workload identity trust
# Advantage: Provides App Registration linkage for lifecycle and developer ownership actions
# Advantage: App-only authentication enables non-interactive scheduled audits and automation
# CSV column: ObjectType indicates record type, aids filtering and automation
# CSV column: AppOwnerOrganizationId reveals application owning tenant for multi-tenant tracking
# CSV column: ServicePrincipalType distinguishes managed identities from application principals
# CSV column: Id provides the SP object id for targeted Graph remediation
# CSV column: DisplayName gives a human-friendly identifier for tickets and reviews
# CSV column: AppId links sign-ins and app registrations to the SP
# CSV column: Tags classify SPs for automated policies or scope-based reviews
# CSV column: SignInAudience highlights intended scope and potential external exposure
# CSV column: PasswordCount surfaces number of client secrets requiring rotation oversight
# CSV column: NextCredentialExpiry shows the nearest expiry for rotation planning
# CSV column: NextExpiryDays gives urgency for scheduling credential replacement
# CSV column: ExpiringSoon flags credentials within the configured expiry window
# CSV column: PreferredSingleSignOnMode documents SSO configuration affecting authentication flows
# CSV column: PreferredTokenSigningKeyThumbprint helps troubleshoot token validation and rollover
# CSV column: Homepage and LoginUrl validate declared application endpoints for legitimacy
# CSV column: ReplyUrls lists redirect URIs to audit OAuth redirect configurations
# CSV column: ServicePrincipalNames lists aliases used for discovery and de-duplication
# CSV column: NotificationEmailAddresses provides contacts for operational notifications and alerts
# CSV column: AccountEnabled indicates whether the SP is active for quick quarantine decisions
# CSV column: AppRoleAssignmentRequired and AppRoles reveal authorization patterns and privileges
# CSV column: ServicePrincipalOwners identifies responsible owners for notifications and approvals
# CSV column: AppReg_Name and AppReg_ObjectId cross-reference the application registration
# CSV column: AppReg_KeyCredentials and status expose certificate expiry and replacement needs
# CSV column: AppReg_PasswordCredentials and status reveal client secret lifecycle information
# CSV column: AppReg_FederatedCredentials surfaces external identity federation bindings for review
# CSV column: LastSignIn and SignInCount help find unused or suspicious Service Principals
# CSV column: AdditionalProperties preserves other SP attributes for deeper diagnostics

#############################################################################################################################################
# TROUBLESHOOTING ( potential, and in case of different setups in your VSCode/Powershell environment )                                      #
#############################################################################################################################################

# Install NuGet provider if missing (required for PSGallery installs)
# Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

# Trust PSGallery if required
# Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Install Microsoft Graph authentication module (for Connect-MgGraph)
# Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force

# Install Microsoft Graph Applications module (for Get-MgApplication, Get-MgServicePrincipal)
# Install-Module -Name Microsoft.Graph.Applications -Scope CurrentUser -Force

# Install Microsoft Graph Users module (for Get-MgUser, Get-MgServicePrincipalOwner)
# Install-Module -Name Microsoft.Graph.Users -Scope CurrentUser -Force

# Optionally install the full Microsoft.Graph meta-module instead of individual modules
# Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force

# Update installed Graph modules to latest versions
# Update-Module -Name Microsoft.Graph.Authentication,Microsoft.Graph.Applications,Microsoft.Graph.Users

# Import modules explicitly before running the script (PowerShell will auto-load but explicit import is recommended)
# Import-Module Microsoft.Graph.Authentication
# Import-Module Microsoft.Graph.Applications
# Import-Module Microsoft.Graph.Users


#############################################################################################################################################
# This script main logic was authored by COPILOT using general knowledge of Microsoft Graph and PowerShell programming patterns             #
# Several human interactions (Agustin Borrajo) around code refactoring took place until it worked as proposed.                              #
#############################################################################################################################################

$TenantId = $env:MG_TENANTID
$ClientId = $env:MG_CLIENTID
$ClientSecret = $env:MG_CLIENTSECRET  
$OutputFolder   = ".\Entra_Service_Principal_Audit"
$LookbackDays   = 90
$ExpiryWindowDays = 30


# --- Validation / prepare ---
if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
  Write-Error "TenantId, ClientId and ClientSecret must be provided."
  return
}
if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory | Out-Null }

# --- Load modules and connect (app-only) ---
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Users -ErrorAction Stop

Write-Host "Connecting to Microsoft Graph (app-only)..."
$secPwd = ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
$clientSecretCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ClientId, $secPwd
try {
  Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $clientSecretCred
} catch {
  Write-Error "Connect-MgGraph failed: $_"
  return
}
Get-MgContext | Out-Null

# --- Cutoff / sign-in lookup (best-effort) ---
$cutoff = (Get-Date).AddDays(-$LookbackDays)
Write-Host "LookbackDays: $LookbackDays  cutoff: $cutoff"
$appSignInLookup = @{}
try {
  $filter = "createdDateTime ge $($cutoff.ToUniversalTime().ToString('o'))"
  $signIns = Get-MgAuditLogSignIn -All -Filter $filter -ErrorAction Stop | Select-Object Id,CreatedDateTime,AppId
  $grouped = $signIns | Group-Object -Property AppId
  foreach ($g in $grouped) {
    $appId = $g.Name
    $last = ($g.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
    $count = $g.Count
    $appSignInLookup[$appId] = [PSCustomObject]@{ AppId = $appId; LastSignIn = $last; SignInCount = $count }
  }
} catch {
  Write-Warning "Sign-in logs unavailable or failed: $($_.Exception.Message)"
  $appSignInLookup = @{}
}

# --- Helpers -----------------------------------------------------------------------

function Invoke-Get {
  param([string]$uri)
  try {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    return $resp
  } catch {
    return $null
  }
}

function Resolve-OwnerString {
  param([psobject]$owner)
  # owner may already include displayName/userPrincipalName/mail/appId depending on type
  if (-not $owner) { return $null }
  $display = $null
  $idpart  = $null
  if ($owner.PSObject.Properties.Name -contains 'displayName' -and $owner.displayName) { $display = $owner.displayName }
  if ($owner.PSObject.Properties.Name -contains 'userPrincipalName' -and $owner.userPrincipalName) { $idpart = $owner.userPrincipalName }
  elseif ($owner.PSObject.Properties.Name -contains 'mail' -and $owner.mail) { $idpart = $owner.mail }
  elseif ($owner.PSObject.Properties.Name -contains 'appId' -and $owner.appId) { $idpart = $owner.appId }
  elseif ($owner.PSObject.Properties.Name -contains 'id' -and $owner.id) { $idpart = $owner.id }
  if ($display) { return ("{0} <{1}>" -f $display, $idpart) } else { return $idpart }
}

function Get-SpOwnersString {
  param([string]$ServicePrincipalId)
  try {
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/owners`?\$select=id,displayName,userPrincipalName,mail,appId"
    $resp = Invoke-Get $uri
    if (-not $resp -or -not $resp.value) { return $null }
    $owners = @()
    foreach ($o in $resp.value) {
      $owners += (Resolve-OwnerString -owner $o)
    }
    if ($owners.Count -gt 0) { return ($owners -join ", ") } else { return $null }
  } catch {
    return $null
  }
}

#### Determine status from collection of candidate end dates (DateTime or $null)
function Determine-CredStatus {
  param(
    [object[]]$EndDates = $null,
    [int]$WindowDays = 30
  )
  if (-not $EndDates -or $EndDates.Count -eq 0) { return "CURRENT" }
  $now = Get-Date
  $soonThreshold = $now.AddDays($WindowDays)

  $expired = $false; $soon = $false
  foreach ($d in $EndDates) {
    if (-not $d) { continue }
    $dt = if ($d -is [string]) { [datetime]$d } else { [datetime]$d }
    if ($dt -lt $now) { $expired = $true; break }
    if ($dt -le $soonThreshold) { $soon = $true }
  }
  if ($expired) { return "EXPIRED" }
  if ($soon)    { return "SOON" }
  return "CURRENT"
}

function Get-AppRegistrationDetails {
  param([string]$AppId)
  $result = [ordered]@{
    AppReg_Name = $null
    AppReg_ObjectId = $null
    AppReg_KeyCredentials = $null
    AppReg_KeyCredentials_Status = $null
    AppReg_PasswordCredentials = $null
    AppReg_PasswordCredentials_Status = $null
    AppReg_FederatedCredentials = $null
  }
  if (-not $AppId) { return $result }

  # 1) Lookup application object id
  $appLookup = Invoke-Get "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$AppId'&`$select=id,displayName"
  if (-not $appLookup -or -not $appLookup.value -or $appLookup.value.Count -eq 0) { return $result }
  $appObj = $appLookup.value[0]
  $appObjId = $appObj.id
  $result.AppReg_Name = $appObj.displayName
  $result.AppReg_ObjectId = $appObjId

  # Prepare arrays to collect end dates as DateTime objects (used by Determine-CredStatus)
  $keyEndDates = @()
  $passEndDates = @()

  # 2) Read keyCredentials and passwordCredentials (v1) using SDK (strongly typed)
  try {
    $appFull = Get-MgApplication -ApplicationId $appObjId -Property keyCredentials,passwordCredentials -ErrorAction Stop
  } catch {
    $appFull = $null
  }

  if ($appFull) {
    # Key credentials (certs)
    if ($appFull.keyCredentials -and $appFull.keyCredentials.Count -gt 0) {
      $kc = @()
      foreach ($k in $appFull.keyCredentials) {
        $label = $null
        if ($k.PSObject.Properties.Name -contains 'displayName' -and $k.displayName) { $label = $k.displayName }
        elseif ($k.PSObject.Properties.Name -contains 'customKeyIdentifier' -and $k.customKeyIdentifier) {
          # customKeyIdentifier is a byte[]; prefer hex for readability
          try { $label = -join ($k.customKeyIdentifier | ForEach-Object { $_.ToString('x2') }) } catch { $label = $k.customKeyIdentifier }
        }
        elseif ($k.PSObject.Properties.Name -contains 'keyId' -and $k.keyId) { $label = $k.keyId }
        else { $label = $k.id }

        $end = $null
        if ($k.PSObject.Properties.Name -contains 'endDateTime' -and $k.endDateTime) {
          $dt = [datetime]$k.endDateTime
          $end = $dt.ToString('yyyy-MM-dd')
          $keyEndDates += $dt
        }
        if ($end) { $kc += ("{0} (end={1})" -f $label, $end) } else { $kc += $label }
      }
      if ($kc.Count -gt 0) { $result.AppReg_KeyCredentials = ($kc -join "; ") }
    }

    # Password credentials (client secrets)
    if ($appFull.passwordCredentials -and $appFull.passwordCredentials.Count -gt 0) {
      $pc = @()
      foreach ($p in $appFull.passwordCredentials) {
        $label = if ($p.PSObject.Properties.Name -contains 'displayName' -and $p.displayName) { $p.displayName }
                 elseif ($p.PSObject.Properties.Name -contains 'keyId' -and $p.keyId) { $p.keyId } else { $p.id }

        $end = $null
        if ($p.PSObject.Properties.Name -contains 'endDateTime' -and $p.endDateTime) {
          $dt = [datetime]$p.endDateTime
          $end = $dt.ToString('yyyy-MM-dd')
          $passEndDates += $dt
        }
        if ($end) { $pc += ("{0} (end={1})" -f $label, $end) } else { $pc += $label }
      }
      if ($pc.Count -gt 0) { $result.AppReg_PasswordCredentials = ($pc -join "; ") }
    }
  }

  # 3) Federated credentials (beta) - optional, may require Application.Read.All and beta usage
  try {
    $fed = Invoke-Get "https://graph.microsoft.com/beta/applications/$appObjId/federatedIdentityCredentials"
    if ($fed -and $fed.value -and $fed.value.Count -gt 0) {
      $fe = @()
      foreach ($f in $fed.value) {
        $name = if ($f.PSObject.Properties.Name -contains 'name' -and $f.name) { $f.name } else { $null }
        $sub  = if ($f.PSObject.Properties.Name -contains 'subject' -and $f.subject) { $f.subject } else { $null }
        $iss  = if ($f.PSObject.Properties.Name -contains 'issuer'  -and $f.issuer)  { $f.issuer  } else { $null }
        if ($name) { $fe += $name }
        elseif ($sub -and $iss) { $fe += ("{0}@{1}" -f $sub, $iss) }
        elseif ($sub) { $fe += $sub } else { $fe += $f.id }
      }
      if ($fe.Count -gt 0) { $result.AppReg_FederatedCredentials = ($fe -join "; ") }
    }
  } catch {
    # ignore beta failures
  }

  # Determine statuses using collected DateTime arrays
  $result.AppReg_KeyCredentials_Status = Determine-CredStatus -EndDates $keyEndDates -WindowDays $ExpiryWindowDays
  $result.AppReg_PasswordCredentials_Status = Determine-CredStatus -EndDates $passEndDates -WindowDays $ExpiryWindowDays

  return $result
}

# --- Query service principals -------------------------------------------------------
$filterQuery = "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
Write-Host "Querying service principals (filter: $filterQuery)..."
$svcPrincipals = Get-MgServicePrincipal -Filter $filterQuery -All |
  Select-Object AppOwnerOrganizationId,Id,AppDisplayName,DisplayName,AppId,ServicePrincipalType,Tags,SignInAudience,PasswordCredentials,PreferredSingleSignOnMode,PreferredTokenSigningKeyThumbprint,Homepage,LoginUrl,ReplyUrls,ServicePrincipalNames,AccountEnabled,AppRoleAssignmentRequired,AppRoles,AdditionalProperties,NotificationEmailAddresses

# Determine max number of credentials across all SPs
$maxCreds = ($svcPrincipals | ForEach-Object { if ($_.PasswordCredentials) { $_.PasswordCredentials.Count } else { 0 } } | Measure-Object -Maximum).Maximum
if (-not $maxCreds) { $maxCreds = 0 }
Write-Host "Max password credentials per SP detected: $maxCreds"

# Build header columns (single CSV)
$baseProps = @(
  "ObjectType","AppOwnerOrganizationId","ServicePrincipalType","Id","DisplayName","AppDisplayName","AppId","Tags","SignInAudience",
  "PasswordCount","NextCredentialExpiry","NextExpiryDays","ExpiringSoon",
  "PreferredSingleSignOnMode","PreferredTokenSigningKeyThumbprint","Homepage","LoginUrl","ReplyUrls","ServicePrincipalNames","NotificationEmailAddresses",
  "AccountEnabled","AppRoleAssignmentRequired","AppRoles","ServicePrincipalOwners",
  "AppReg_Name","AppReg_ObjectId","AppReg_KeyCredentials","AppReg_KeyCredentials_Status","AppReg_PasswordCredentials","AppReg_PasswordCredentials_Status","AppReg_FederatedCredentials",
  "LastSignIn","SignInCount","AdditionalProperties"
)
$credProps = @()
for ($i = 1; $i -le $maxCreds; $i++) {
  $credProps += "Credential${i}_DisplayName"
  $credProps += "Credential${i}_KeyId"
  $credProps += "Credential${i}_StartDateTime"
  $credProps += "Credential${i}_EndDateTime"
  $credProps += "Credential${i}_Hint"
  $credProps += "Credential${i}_SecretTextPresent"
  $credProps += "Credential${i}_CustomKeyIdentifier"
}
$allProps = $baseProps + $credProps

# Collect rows
$rows = @()
foreach ($sp in $svcPrincipals) {
  $appId = $sp.AppId
  $stat = $null
  if ($appId -and $appSignInLookup.ContainsKey($appId)) { $stat = $appSignInLookup[$appId] }

  # Flatten SP password credentials
  $spCreds = @()
  if ($sp.PasswordCredentials) {
    foreach ($cred in $sp.PasswordCredentials) {
      $spCreds += [PSCustomObject]@{
        DisplayName = $cred.DisplayName
        KeyId = $cred.KeyId
        StartDateTime = if ($cred.StartDateTime) { [datetime]$cred.StartDateTime } else { $null }
        EndDateTime = if ($cred.EndDateTime) { [datetime]$cred.EndDateTime } else { $null }
        Hint = $cred.Hint
        SecretTextPresent = if ($cred.SecretText) { "Yes" } else { "No" }
        CustomKeyIdentifier = if ($cred.CustomKeyIdentifier) { ($cred.CustomKeyIdentifier -join ",") } else { $null }
      }
    }
  }

  # Credential summary
  $passwordCount = $spCreds.Count
  $nextExpiry = $null; $nextExpiryDays = $null; $expiringSoon = $false
  if ($passwordCount -gt 0) {
    $ordered = $spCreds | Where-Object { $_.EndDateTime -ne $null } | Sort-Object EndDateTime
    if ($ordered.Count -gt 0) {
      $nextExpiry = $ordered[0].EndDateTime
      $nextExpiryDays = [math]::Round((($nextExpiry) - (Get-Date)).TotalDays, 1)
      $expiringSoon = ($nextExpiry -le (Get-Date).AddDays($ExpiryWindowDays))
    }
  }

  # AppRoles readable: prefer displayName then value then id
  $appRolesText = $null
  if ($sp.AppRoles -and $sp.AppRoles.Count -gt 0) {
    $roleNames = @()
    foreach ($r in $sp.AppRoles) {
      if ($r.PSObject.Properties.Name -contains 'displayName' -and $r.displayName) { $roleNames += $r.displayName }
      elseif ($r.PSObject.Properties.Name -contains 'value' -and $r.value) { $roleNames += $r.value }
      elseif ($r.PSObject.Properties.Name -contains 'id' -and $r.id) { $roleNames += $r.id }
    }
    if ($roleNames.Count -gt 0) { $appRolesText = ($roleNames -join ", ") }
  }

  # Owners
  #  $ownersText = Get-SpOwnersString -ServicePrincipalId $sp.Id
  #  $ownersText = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All | ForEach-Object { $_.AdditionalProperties['displayName'] }
  $ownersText = (Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -All | ForEach-Object { ($_.AdditionalProperties['displayName'] -join ',') } | Where-Object { $_ }) -join ' ; '

  # App registration details
  $appReg = Get-AppRegistrationDetails -AppId $sp.AppId

  # Build ordered object
  $obj = [ordered]@{
    ObjectType = "ServicePrincipal"
    AppOwnerOrganizationId = $sp.AppOwnerOrganizationId
    ServicePrincipalType = $sp.ServicePrincipalType
    Id = $sp.Id
    DisplayName = $sp.DisplayName
    AppDisplayName = $sp.AppDisplayName
    AppId = $sp.AppId
    Tags = if ($sp.Tags) { ($sp.Tags -join ";") } else { $null }
    SignInAudience = $sp.SignInAudience
    PasswordCount = $passwordCount
    NextCredentialExpiry = if ($nextExpiry) { $nextExpiry.ToString("o") } else { $null }
    NextExpiryDays = $nextExpiryDays
    ExpiringSoon = $expiringSoon
    PreferredSingleSignOnMode = $sp.PreferredSingleSignOnMode
    PreferredTokenSigningKeyThumbprint = $sp.PreferredTokenSigningKeyThumbprint
    Homepage = $sp.Homepage
    LoginUrl = $sp.LoginUrl
    ReplyUrls = if ($sp.ReplyUrls) { ($sp.ReplyUrls -join ";") } else { $null }
    ServicePrincipalNames = if ($sp.ServicePrincipalNames) { ($sp.ServicePrincipalNames -join ";") } else { $null }
    NotificationEmailAddresses = if ($sp.NotificationEmailAddresses) { ($sp.NotificationEmailAddresses -join ";") } else { $null }
    AccountEnabled = $sp.AccountEnabled
    AppRoleAssignmentRequired = $sp.AppRoleAssignmentRequired
    AppRoles = $appRolesText
    ServicePrincipalOwners = $ownersText
    AppReg_Name = $appReg.AppReg_Name
    AppReg_ObjectId = $appReg.AppReg_ObjectId
    AppReg_KeyCredentials = $appReg.AppReg_KeyCredentials
    AppReg_KeyCredentials_Status = $appReg.AppReg_KeyCredentials_Status
    AppReg_PasswordCredentials = $appReg.AppReg_PasswordCredentials
    AppReg_PasswordCredentials_Status = $appReg.AppReg_PasswordCredentials_Status
    AppReg_FederatedCredentials = $appReg.AppReg_FederatedCredentials
    LastSignIn = if ($stat) { $stat.LastSignIn } else { $null }
    SignInCount = if ($stat) { $stat.SignInCount } else { 0 }
    AdditionalProperties = if ($sp.AdditionalProperties) { ($sp.AdditionalProperties | ConvertTo-Json -Compress) } else { $null }
  }

  # Add credential columns up to $maxCreds
  for ($i = 0; $i -lt $maxCreds; $i++) {
    $slot = $i + 1
    if ($i -lt $spCreds.Count) {
      $c = $spCreds[$i]
      $obj["Credential${slot}_DisplayName"] = $c.DisplayName
      $obj["Credential${slot}_KeyId"] = $c.KeyId
      $obj["Credential${slot}_StartDateTime"] = if ($c.StartDateTime) { $c.StartDateTime.ToString("o") } else { $null }
      $obj["Credential${slot}_EndDateTime"] = if ($c.EndDateTime) { $c.EndDateTime.ToString("o") } else { $null }
      $obj["Credential${slot}_Hint"] = $c.Hint
      $obj["Credential${slot}_SecretTextPresent"] = $c.SecretTextPresent
      $obj["Credential${slot}_CustomKeyIdentifier"] = $c.CustomKeyIdentifier
    } else {
      $obj["Credential${slot}_DisplayName"] = $null
      $obj["Credential${slot}_KeyId"] = $null
      $obj["Credential${slot}_StartDateTime"] = $null
      $obj["Credential${slot}_EndDateTime"] = $null
      $obj["Credential${slot}_Hint"] = $null
      $obj["Credential${slot}_SecretTextPresent"] = $null
      $obj["Credential${slot}_CustomKeyIdentifier"] = $null
    }
  }

  $rows += New-Object PSObject -Property $obj
}

# --- Export CSV (single file) ---
$timestamp = (Get-Date).ToString('yyyy-MM-dd_HHmm')
$tsWithHs = "${timestamp}hs"
$svcFilename = "Entra_Service_Principal_Audit_$tsWithHs.csv"
$svcCsv = Join-Path $OutputFolder $svcFilename

$exportRows = $rows | Select-Object $allProps
$exportRows | Export-Csv -Path $svcCsv -NoTypeInformation -Encoding UTF8

Write-Host "Export complete: $($exportRows.Count) rows -> $svcCsv"

Disconnect-MgGraph