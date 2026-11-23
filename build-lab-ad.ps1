#requires -Modules ActiveDirectory
<#
    build-lab-ad.ps1
    ----------------
    Bygger en AVSIKTLIGT sårbar Active Directory-miljö för ett säkerhetslabb.

    *** KÖR ENDAST i ett isolerat labbnät. Deploya ALDRIG i produktion. ***

    Körs på domänkontrollanten, i en upphöjd (Run as Administrator)
    PowerShell, efter att domänen är skapad med Install-ADDSForest.

    Skriptet är idempotent: kör det hur många gånger du vill. Allt det
    skapar hamnar under OU:n "Lab", så du river labbet med en rad:

        Get-ADOrganizationalUnit -Filter "Name -eq 'Lab'" |
            Set-ADObject -ProtectedFromAccidentalDeletion $false -PassThru |
            Remove-ADOrganizationalUnit -Recursive -Confirm:$false
#>

$ErrorActionPreference = 'Stop'

# --- 0. Domänen (läses ut automatiskt) -----------------------------------
$baseDN = (Get-ADDomain).DistinguishedName        # t.ex. DC=lab,DC=local
$dns    = (Get-ADDomain).DNSRoot                   # t.ex. lab.local
$labOU  = "OU=Lab,$baseDN"

Write-Host "Bygger labb i domänen $dns" -ForegroundColor Cyan

# Labblösenord. Medvetet svaga/vanliga – det är hela poängen.
$pwWeak   = ConvertTo-SecureString 'Password1'   -AsPlainText -Force   # svc-konto, knäckbart
$pwNormal = ConvertTo-SecureString 'Host2027!x'  -AsPlainText -Force   # vanliga användare
$pwSpray  = 'Sommar2026!'   # klartext med flit: lösenordet du "sprayar" i fas 2

# Hjälpfunktion: skapa en OU bara om den inte finns
function Ensure-OU($name, $path) {
    $dn = "OU=$name,$path"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $name -Path $path -ProtectedFromAccidentalDeletion $false
    }
    return $dn
}

# --- 1. OU-struktur -------------------------------------------------------
$null       = Ensure-OU 'Lab'       $baseDN
$ouUsers    = Ensure-OU 'Users'     $labOU
$ouAdmins   = Ensure-OU 'Admins'    $labOU
$ouService  = Ensure-OU 'Service'   $labOU

# --- 2. Grupper -----------------------------------------------------------
function Ensure-Group($name, $path, $scope = 'Global') {
    if (-not (Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $name -GroupScope $scope -Path $path
    }
    return (Get-ADGroup -Identity $name)
}

$gHelpdesk = Ensure-Group 'Helpdesk'   $ouUsers
$gIT       = Ensure-Group 'IT-Support' $ouAdmins
$gFinance  = Ensure-Group 'Ekonomi'    $ouUsers

# --- 3. Vanliga användare (en loop – lär dig mönstret) -------------------
$fornamn = 'anna','erik','sara','johan','lisa','karl','emma','olof',
           'nina','per','maja','sven','elin','gustav','hanna','ali',
           'sofia','david','elsa','omar','klara','viktor','tuva','noa'

foreach ($namn in $fornamn) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$namn'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $namn -SamAccountName $namn `
            -UserPrincipalName "$namn@$dns" -Path $ouUsers `
            -AccountPassword $pwNormal -Enabled $true `
            -ChangePasswordAtLogon $false
    }
    Add-ADGroupMember -Identity $gHelpdesk -Members $namn -ErrorAction SilentlyContinue
}

# --- 4. Inlagda svagheter (det du attackerar i fas 2) --------------------

# 4a. KERBEROASTING: ett tjänstekonto med SPN och svagt lösenord.
#     En SPN gör kontot "roastbart"; svagt lösenord gör det knäckbart offline.
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc_sql'" -ErrorAction SilentlyContinue)) {
    New-ADUser -Name 'svc_sql' -SamAccountName 'svc_sql' `
        -UserPrincipalName "svc_sql@$dns" -Path $ouService `
        -AccountPassword $pwWeak -Enabled $true `
        -PasswordNeverExpires $true
}
# Sätt SPN separat – robustast över olika Windows-versioner.
Set-ADUser -Identity 'svc_sql' -ServicePrincipalNames @{ Replace = 'MSSQL/sql.lab.local:1433' }

# 4b. LÖSENORD I BESKRIVNING: klassiskt fynd, syns direkt i BloodHound.
Set-ADUser -Identity 'anna' `
    -Description "Tillfälligt lösenord satt av IT: $pwSpray  (ta bort denna rad!)"

# 4c. FÖR BRED BEHÖRIGHET via grupp-nästling:
#     IT-Support läggs in i Domain Admins (fel!), och vanliga användare
#     ligger i IT-Support. Det ger en attackväg mot DA som BloodHound ritar.
Add-ADGroupMember -Identity 'Domain Admins' -Members $gIT -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity $gIT -Members 'erik','sara' -ErrorAction SilentlyContinue

# 4d. PASSWORD SPRAYING-mål: ett par konton där spray-lösenordet funkar.
#     (De andra kontona har $pwNormal, så sprayen hittar bara dessa.)
Set-ADAccountPassword -Identity 'johan' -NewPassword (ConvertTo-SecureString $pwSpray -AsPlainText -Force) -Reset
Set-ADAccountPassword -Identity 'lisa'  -NewPassword (ConvertTo-SecureString $pwSpray -AsPlainText -Force) -Reset

Write-Host "Klart. Byggde:" -ForegroundColor Green
Write-Host "  - $($fornamn.Count) användare i OU=Lab"
Write-Host "  - svc_sql med SPN (Kerberoasting-mål)"
Write-Host "  - lösenord i beskrivning på 'anna'"
Write-Host "  - IT-Support nästlad i Domain Admins (attackväg)"
Write-Host "  - johan/lisa med spray-lösenordet '$pwSpray'"
