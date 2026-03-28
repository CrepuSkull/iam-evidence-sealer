<#
.SYNOPSIS
    Crée un certificat X.509 CodeSigning auto-signé pour tests et démonstrations.

.DESCRIPTION
    New-SelfSignedCert.ps1 génère un certificat de signature de code auto-signé
    dans le magasin utilisateur Windows (Cert:\CurrentUser\My).

    ⚠  AVERTISSEMENT JURIDIQUE IMPORTANT :
    Un certificat auto-signé garantit l'intégrité TECHNIQUE d'un fichier signé
    (personne n'a modifié le fichier après la signature), MAIS il n'a AUCUNE
    valeur juridique reconnue par un tiers indépendant.

    Pour une valeur PROBANTE en contexte réglementaire (FINMA, CSSF, DORA) :
    → Certificat émis par une CA commerciale reconnue (Sectigo, DigiCert)
    → COMBINÉ à l'horodatage RFC 3161 (-Timestamp dans Invoke-SecureAudit.ps1)

    Cas d'usage de ce script :
      ✅ Démonstrations techniques
      ✅ Tests locaux du pipeline de scellage
      ✅ GitHub (illustration du mécanisme)
      ✅ Audits internes sans exigence réglementaire externe
      ❌ Rapports destinés à FINMA / CSSF / régulateurs

.PARAMETER Subject
    Nom affiché dans le certificat.
    Défaut : "CN=Arnaud Montcho (Audit Demo)"

.PARAMETER ValidityYears
    Durée de validité en années.
    Défaut : 1

.PARAMETER ExportPfx
    Exporte également le certificat + clé privée en .pfx (protégé par mot de passe).
    ⚠  Ne partagez JAMAIS ce fichier .pfx — il contient la clé privée.

.EXAMPLE
    .\New-SelfSignedCert.ps1
    .\New-SelfSignedCert.ps1 -Subject "CN=Demo Audit Client" -ValidityYears 2
    .\New-SelfSignedCert.ps1 -ExportPfx

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    GitHub  : https://github.com/CrepuSkull/iam-evidence-sealer
    Windows uniquement (New-SelfSignedCertificate est natif PowerShell/Windows)
#>

param (
    [string]$Subject       = "CN=Arnaud Montcho (Audit Demo)",
    [int]   $ValidityYears = 1,
    [switch]$ExportPfx
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
Write-Host "║         NEW-SELFSIGNEDCERT — CERTIFICAT DE TEST         ║" -ForegroundColor Yellow
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ⚠  RAPPEL : Certificat auto-signé = démonstration technique uniquement" -ForegroundColor Yellow
Write-Host "  ⚠  Pour FINMA/CSSF : certificat CA commerciale + horodatage RFC 3161" -ForegroundColor Yellow
Write-Host ""

# Vérification que le certificat n'existe pas déjà
$Existing = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date) }

if ($Existing) {
    Write-Host "  Un certificat valide existe déjà :" -ForegroundColor Cyan
    Write-Host "  Subject    : $($Existing.Subject)" -ForegroundColor White
    Write-Host "  Thumbprint : $($Existing.Thumbprint)" -ForegroundColor White
    Write-Host "  Expire le  : $($Existing.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor White
    Write-Host ""
    $Choice = Read-Host "  Créer un nouveau certificat quand même ? (o/N)"
    if ($Choice -notmatch '^[oO]$') {
        Write-Host "  → Certificat existant conservé." -ForegroundColor Green
        exit 0
    }
}

# Création du certificat
Write-Host "  Création du certificat..." -ForegroundColor Cyan

$Cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $Subject `
    -KeySpec Signature `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears($ValidityYears) `
    -CertStoreLocation "Cert:\CurrentUser\My"

Write-Host ""
Write-Host "  ✅ Certificat créé avec succès :" -ForegroundColor Green
Write-Host "  Subject    : $($Cert.Subject)" -ForegroundColor White
Write-Host "  Thumbprint : $($Cert.Thumbprint)" -ForegroundColor White
Write-Host "  Valide du  : $($Cert.NotBefore.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "  Expire le  : $($Cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "  Stocké     : Cert:\CurrentUser\My\$($Cert.Thumbprint)" -ForegroundColor White
Write-Host ""

# Ajout aux autorités de confiance racine (nécessaire pour que la signature soit "Valid" plutôt que "UnknownError")
Write-Host "  Ajout aux autorités de confiance (CurrentUser\Root)..." -ForegroundColor Cyan
$RootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
$RootStore.Open("ReadWrite")
$RootStore.Add($Cert)
$RootStore.Close()
Write-Host "  ✅ Ajouté à CurrentUser\Root" -ForegroundColor Green
Write-Host ""

# Export PFX optionnel
if ($ExportPfx) {
    $PfxPath = ".\AuditDemo_$(Get-Date -Format 'yyyyMMdd').pfx"
    $PfxPassword = Read-Host "  Mot de passe pour le fichier .pfx" -AsSecureString

    $Cert | Export-PfxCertificate `
        -FilePath $PfxPath `
        -Password $PfxPassword | Out-Null

    Write-Host "  ✅ Export PFX : $PfxPath" -ForegroundColor Green
    Write-Host "  ⚠  IMPORTANT : Ne commitez JAMAIS ce fichier .pfx sur GitHub" -ForegroundColor Red
    Write-Host "     Ajoutez *.pfx à votre .gitignore" -ForegroundColor Red
    Write-Host ""
}

Write-Host "  → Vous pouvez maintenant exécuter :" -ForegroundColor Cyan
Write-Host "     .\Invoke-SecureAudit.ps1 -ScriptPath <script> -Client <nom> -Sign" -ForegroundColor White
Write-Host ""
