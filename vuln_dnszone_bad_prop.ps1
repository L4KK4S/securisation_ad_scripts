<#
.SYNOPSIS
    Vérification du point de contrôle "vuln_dnszone_bad_prop" sur la sécurisation de l'AD par l'ANSSI

.DESCRIPTION
    Ce script vérifie la valeur 'AllowUpdate' des zones DNS en tapant sur le registre Windows.
    Il indique la valeur de cet argument et si c'est conforme ou pas, on a deux types de conformité, la 1 et la 3.

.EXAMPLE
    >> .\vuln_dnszone_bad_prop.ps1
    
    # ============================================================ #
    #   Vérification du point de contôle 'vuln_dnszone_bad_prop'   #
    # ============================================================ #

    [Niveau 3] 1.168.192.in-addr.arpa              : NON CONFORME   (Aucun (0))
    [Niveau 1] rs1prj5.lan                         : CONFORME       (Sécurisé (2))
    [Niveau 3] TrustAnchors                        : NON CONFORME   (Inexistant)
    [Niveau 1] _msdcs.rs1prj5.lan                  : NON CONFORME   (Non-Sécurisé (1))

    .NOTES
        Auteur: Abdel-Waheb SAKKAL
        Date: 14/04/2026
    #>


# Variables
$domain = (Get-ADDomain).DNSRoot
$msdcs  = "_msdcs.$((Get-ADForest).RootDomain)"
$pathRegister = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones"

# Bannière au début du script
Write-Host "`n`n#" ("=" * 60) "#`n#   Vérification du point de contôle 'vuln_dnszone_bad_prop'   #`n#" ("=" * 60) "#`n"

# On parcourt chaque objet de notre registre
Get-ChildItem -Path $pathRegister | ForEach-Object {
    
    # on récupère le nom de la zone
    $nameZone = $_.PSChildName
    #Write-Host "[DEBUG] nom de la zone : $($nameZone)"

    # on récupère la valeur de notre variable
    $val = (Get-ItemProperty -Path $_.PSPath -Name "AllowUpdate" -ErrorAction SilentlyContinue).AllowUpdate
    #Write-Host "[DEBUG] nom de la zone : $($val)"   

    # si c'est vide, on considère que c'est -1 car ça na pas été activé
    if ($null -eq $Val) { $Val = -1 }

    # traitement des résultats
    $isCritical = ($nameZone -eq $domain -or $nameZone -eq $msdcs)
    $level      = if ($IsCritical) { "Niveau 1" } else { "Niveau 3" }
    $isConform  = ($Val -eq 2)
    $status     = if ($IsConform) { "CONFORME" } else { "NON CONFORME" }
    $color      = if ($IsConform) { "Green" } else { "Red" }

    # valeur finale à afficher
    $mode = switch($Val) { 
        -1 { "Inexistant"}
        0 { "Aucun (0)" } 
        1 { "Non-sécurisé et sécurisé (1)" } 
        2 { "Sécurisé uniquement (2)" } 
        default { "Inconnu ($Val)" }
    }

    # affichage du résultat
    Write-Host "[$level] " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($nameZone.PadRight(35)) : " -NoNewline
    Write-Host "$status".PadRight(15) -ForegroundColor $Color -NoNewline
    Write-Host "($mode)"
}

Write-Host "`n"
