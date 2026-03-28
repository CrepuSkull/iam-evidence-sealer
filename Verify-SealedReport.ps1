<#
.SYNOPSIS
    Vérifie l'intégrité et la signature d'un rapport d'audit scellé.

.DESCRIPTION
    Verify-SealedReport.ps1 permet à n'importe quel destinataire de vérifier
    qu'un rapport livré par Arnaud Montcho n'a pas été modifié depuis sa génération.

    Vérifications effectuées (selon les fichiers présents) :
      [1] Hash SHA-256     → Intégrité du fichier rapport
      [2] Signature X.509  → Authenticité et non-répudiation
      [3] Manifeste JSON   → Cohérence des métadonnées
      [4] Token RFC 3161   → Horodatage certifié (si présent)

    Ce script est conçu pour être utilisable par un non-technicien :
    il suffit de pointer vers le fichier rapport (.csv, .json, .md).
    Le script localise automatiquement les fichiers de preuve associés.

.PARAMETER ReportPath
    Chemin vers le rapport à vérifier.
    Les fichiers .sha256, .manifest, .tsr sont cherchés automatiquement.

.PARAMETER Strict
    En mode strict, toute vérification manquante est signalée comme ÉCHEC
    plutôt que comme AVERTISSEMENT.

.EXAMPLE
    .\Verify-SealedReport.ps1 -ReportPath ".\Final_Audits\Rapport_Audit_AD_2026-03-26.csv"
    .\Verify-SealedReport.ps1 -ReportPath ".\rapport.csv" -Strict

.OUTPUTS
    Code de sortie 0 = Toutes les vérifications disponibles ont réussi
    Code de sortie 1 = Au moins une vérification a échoué
    Code de sortie 2 = Fichiers de preuve insuffisants pour conclure

.NOTES
    Auteur  : Arnaud Montcho — Consultant IAM/IGA
    GitHub  : https://github.com/CrepuSkull/iam-evidence-sealer
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ReportPath,

    [switch]$Strict
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$OverallResult = 0  # 0=OK, 1=FAIL, 2=INCOMPLETE
$Checks        = @()

function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    $script:Checks += [PSCustomObject]@{ Name = $Name; Status = $Status; Detail = $Detail }
    if ($Status -eq "FAIL") { $script:OverallResult = 1 }
    if ($Status -eq "MISSING" -and $script:Strict) { $script:OverallResult = 1 }
    if ($Status -eq "MISSING" -and -not $script:Strict -and $script:OverallResult -ne 1) { $script:OverallResult = 2 }
}

# ─────────────────────────────────────────────
# EN-TÊTE
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        VERIFY-SEALEDREPORT — VÉRIFICATION INTÉGRITÉ     ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Rapport : $ReportPath" -ForegroundColor White
Write-Host "  Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
if ($Strict) { Write-Host "  Mode    : STRICT (fichiers manquants = ÉCHEC)" -ForegroundColor Yellow }
Write-Host ""

# ─────────────────────────────────────────────
# VÉRIFICATION 1 — HASH SHA-256
# ─────────────────────────────────────────────

Write-Host "  [1/4] Vérification du hash SHA-256..." -ForegroundColor Cyan

$HashFile = "${ReportPath}.sha256"

if (-not (Test-Path $HashFile)) {
    Add-Check "SHA-256" "MISSING" "Fichier .sha256 introuvable : $HashFile"
    Write-Host "       ⬜ ABSENT — Fichier .sha256 manquant" -ForegroundColor Gray
} else {
    # Lecture du hash de référence
    $StoredLine  = (Get-Content $HashFile -Raw).Trim()
    $StoredHash  = ($StoredLine -split '\s+')[0].ToUpper()

    # Calcul du hash actuel
    $CurrentHash = (Get-FileHash -Path $ReportPath -Algorithm SHA256).Hash.ToUpper()

    if ($CurrentHash -eq $StoredHash) {
        Add-Check "SHA-256" "OK" "Hash correspondant : $CurrentHash"
        Write-Host "       ✅ OK — Hash SHA-256 vérifié : $CurrentHash" -ForegroundColor Green
    } else {
        Add-Check "SHA-256" "FAIL" "Hash attendu : $StoredHash | Hash calculé : $CurrentHash"
        Write-Host "       ❌ ÉCHEC — Le fichier a été MODIFIÉ après scellage !" -ForegroundColor Red
        Write-Host "          Attendu  : $StoredHash" -ForegroundColor Red
        Write-Host "          Calculé  : $CurrentHash" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
# VÉRIFICATION 2 — SIGNATURE AUTHENTICODE
# ─────────────────────────────────────────────

Write-Host "  [2/4] Vérification de la signature Authenticode..." -ForegroundColor Cyan

try {
    $SigInfo = Get-AuthenticodeSignature -FilePath $ReportPath -ErrorAction SilentlyContinue

    if ($null -eq $SigInfo -or $SigInfo.Status -eq "NotSigned") {
        Add-Check "Signature" "MISSING" "Aucune signature Authenticode"
        Write-Host "       ⬜ ABSENT — Fichier non signé (niveau L1 Hash uniquement)" -ForegroundColor Gray
    } elseif ($SigInfo.Status -eq "Valid") {
        $Detail = "Signataire : $($SigInfo.SignerCertificate.Subject) | Expire : $($SigInfo.SignerCertificate.NotAfter.ToString('yyyy-MM-dd'))"
        Add-Check "Signature" "OK" $Detail
        Write-Host "       ✅ OK — Signature valide" -ForegroundColor Green
        Write-Host "          Signataire : $($SigInfo.SignerCertificate.Subject)" -ForegroundColor White
        Write-Host "          Expire le  : $($SigInfo.SignerCertificate.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor White

        # Avertissement certificat auto-signé
        if ($SigInfo.SignerCertificate.Issuer -eq $SigInfo.SignerCertificate.Subject) {
            Write-Host "          ⚠  Certificat auto-signé — valeur technique uniquement" -ForegroundColor Yellow
        }
    } elseif ($SigInfo.Status -eq "HashMismatch") {
        Add-Check "Signature" "FAIL" "HashMismatch — Le fichier a été modifié après signature"
        Write-Host "       ❌ ÉCHEC — Signature invalide : le fichier a été modifié après signature !" -ForegroundColor Red
    } else {
        Add-Check "Signature" "WARN" "Statut : $($SigInfo.Status) — $($SigInfo.StatusMessage)"
        Write-Host "       ⚠  AVERTISSEMENT — Statut : $($SigInfo.Status)" -ForegroundColor Yellow
        Write-Host "          $($SigInfo.StatusMessage)" -ForegroundColor Yellow
    }
} catch {
    Add-Check "Signature" "WARN" "Impossible de vérifier : $_"
    Write-Host "       ⚠  Impossible de vérifier la signature : $_" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────
# VÉRIFICATION 3 — MANIFESTE JSON
# ─────────────────────────────────────────────

Write-Host "  [3/4] Vérification du manifeste JSON..." -ForegroundColor Cyan

$ManifestFile = "${ReportPath}.manifest"

if (-not (Test-Path $ManifestFile)) {
    Add-Check "Manifeste" "MISSING" "Fichier .manifest introuvable"
    Write-Host "       ⬜ ABSENT — Fichier .manifest manquant" -ForegroundColor Gray
} else {
    try {
        $Manifest = Get-Content $ManifestFile -Raw | ConvertFrom-Json

        # Vérification cohérence hash dans manifeste vs hash calculé
        $CurrentHash = (Get-FileHash -Path $ReportPath -Algorithm SHA256).Hash.ToUpper()

        if ($Manifest.SHA256.ToUpper() -eq $CurrentHash) {
            Add-Check "Manifeste" "OK" "Hash manifeste cohérent | Client: $($Manifest.Client) | Niveau: $($Manifest.ProofLevel)"
            Write-Host "       ✅ OK — Manifeste cohérent" -ForegroundColor Green
            Write-Host "          Client      : $($Manifest.Client)" -ForegroundColor White
            Write-Host "          Auteur      : $($Manifest.Author)" -ForegroundColor White
            Write-Host "          Date        : $($Manifest.Date)" -ForegroundColor White
            Write-Host "          Script      : $($Manifest.Script)" -ForegroundColor White
            Write-Host "          Niveau      : $($Manifest.ProofLevel)" -ForegroundColor White
            Write-Host "          Run ID      : $($Manifest.RunId)" -ForegroundColor White
        } else {
            Add-Check "Manifeste" "FAIL" "Hash dans manifeste ($($Manifest.SHA256.ToUpper())) ≠ hash calculé ($CurrentHash)"
            Write-Host "       ❌ ÉCHEC — Le hash dans le manifeste ne correspond pas au fichier !" -ForegroundColor Red
        }
    } catch {
        Add-Check "Manifeste" "FAIL" "Manifeste illisible ou corrompu : $_"
        Write-Host "       ❌ ÉCHEC — Manifeste illisible ou corrompu" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
# VÉRIFICATION 4 — TOKEN RFC 3161
# ─────────────────────────────────────────────

Write-Host "  [4/4] Vérification du token RFC 3161..." -ForegroundColor Cyan

$TsrFile = "${ReportPath}.tsr"

if (-not (Test-Path $TsrFile)) {
    Add-Check "RFC3161" "MISSING" "Token .tsr absent — Horodatage certifié non appliqué"
    Write-Host "       ⬜ ABSENT — Pas de token RFC 3161 (niveau L1/L2 uniquement)" -ForegroundColor Gray
} else {
    $OpenSSL = Get-Command openssl -ErrorAction SilentlyContinue
    if ($OpenSSL) {
        try {
            $VerifyOutput = & openssl ts -verify -data $ReportPath -in $TsrFile 2>&1
            if ($VerifyOutput -match "OK") {
                Add-Check "RFC3161" "OK" "Token RFC 3161 valide"
                Write-Host "       ✅ OK — Token RFC 3161 vérifié" -ForegroundColor Green
            } else {
                Add-Check "RFC3161" "FAIL" "Token RFC 3161 invalide : $VerifyOutput"
                Write-Host "       ❌ ÉCHEC — Token RFC 3161 invalide" -ForegroundColor Red
                Write-Host "          $VerifyOutput" -ForegroundColor Red
            }
        } catch {
            Add-Check "RFC3161" "WARN" "Impossible de vérifier le token : $_"
            Write-Host "       ⚠  Impossible de vérifier le token RFC 3161 : $_" -ForegroundColor Yellow
        }
    } else {
        Add-Check "RFC3161" "WARN" "Token .tsr présent mais OpenSSL manquant pour vérification"
        Write-Host "       ⚠  Token .tsr présent mais OpenSSL requis pour vérifier" -ForegroundColor Yellow
        Write-Host "          Installez OpenSSL : https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor White
    }
}

# ─────────────────────────────────────────────
# RÉSUMÉ FINAL
# ─────────────────────────────────────────────

Write-Host ""
Write-Host "  ──────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  RÉSUMÉ DES VÉRIFICATIONS" -ForegroundColor White
Write-Host "  ──────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

foreach ($Check in $Checks) {
    $Icon  = switch ($Check.Status) { "OK" { "✅" } "FAIL" { "❌" } "MISSING" { "⬜" } "WARN" { "⚠ " } default { "  " } }
    $Color = switch ($Check.Status) { "OK" { "Green" } "FAIL" { "Red" } "MISSING" { "Gray" } "WARN" { "Yellow" } default { "White" } }
    Write-Host "  $Icon $($Check.Name.PadRight(15)) $($Check.Status.PadRight(10)) $($Check.Detail)" -ForegroundColor $Color
}

Write-Host ""

$ResultText  = switch ($OverallResult) {
    0 { "✅  INTÉGRITÉ CONFIRMÉE — Toutes les vérifications disponibles ont réussi" }
    1 { "❌  INTÉGRITÉ COMPROMISE — Au moins une vérification a échoué" }
    2 { "⚠   VÉRIFICATION PARTIELLE — Certains fichiers de preuve sont absents" }
}
$ResultColor = switch ($OverallResult) { 0 { "Green" } 1 { "Red" } 2 { "Yellow" } }

Write-Host "  $ResultText" -ForegroundColor $ResultColor
Write-Host ""

exit $OverallResult
