<#
.SYNOPSIS
    Vérification du point de contrôle "vuln_smartcard_expire_passwords" sur la sécurisation de l'AD par l'ANSSI

.DESCRIPTION
    Ce script vérifie si l'attribut 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' est activé sur le domaine
    Cet attribut permet de forcer l'expiration (et donc le renouvellement auto) des mots de passe des comptes 
    utilisant uniquement la carte à puce (YubiKey).

.EXAMPLE
    >> .\vuln_smartcard_expire_passwords.ps1
    
    # ==================================================================== #
    #  Vérification du point de contrôle 'vuln_smartcard_expire_passwords' #
    # ==================================================================== #

    [Niveau 1] rs1prj5.lan                         : CONFORME        (Activé (True))

.NOTES
    Auteur: Abdel-Waheb SAKKAL
    Date: 15/04/2026
#>

# Variables
$domainObj = Get-ADDomain
$domainDN  = $domainObj.DistinguishedName
$domainDNS = $domainObj.DNSRoot

# Bannière au début du script
Write-Host "`n`n#" ("=" * 67) "#`n# Vérification du point de contrôle 'vuln_smartcard_expire_passwords' #`n#" ("=" * 67) "#`n"

# On récupère la valeur de l'attribut msDS-ExpirePasswordsOnSmartCardOnlyAccounts
$val = (Get-ADObject -Identity $domainDN -Properties "msDS-ExpirePasswordsOnSmartCardOnlyAccounts")."msDS-ExpirePasswordsOnSmartCardOnlyAccounts"

# Si la valeur est $null, c'est que l'attribut n'est pas défini 
if ($null -eq $val) { 
    $statusText = "Inexistant/Désactivé"
    $isConform = $false
} else {
    $statusText = if ($val) { "Activé (True)" } else { "Désactivé (False)" }
    $isConform = ($val -eq $true)
}

$status = if ($isConform) { "CONFORME" } else { "NON CONFORME" }
$color  = if ($isConform) { "Green" } else { "Red" }

# Affichage du résultat 
Write-Host "[Niveau 1] " -NoNewline -ForegroundColor DarkGray
Write-Host "$($domainDNS.PadRight(35)) : " -NoNewline
Write-Host "$status".PadRight(15) -ForegroundColor $Color -NoNewline
Write-Host "($statusText)"

Write-Host "`n"
