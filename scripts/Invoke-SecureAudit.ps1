<#
.SYNOPSIS
    Wrapper universel de scellage numérique pour rapports d'audit IAM.

.DESCRIPTION
    Invoke-SecureAudit.ps1 exécute n'importe quel script PowerShell IAM existant
    et enveloppe sa sortie dans un protocole d'intégrité : hash SHA-256, manifeste JSON,
    signature numérique optionnelle (Authenticode), et horodatage certifié RFC 3161.

    Niveaux de preuve disponibles :
      Niveau 1 (défaut)   — Hash SHA-256 + Manifeste JSON
      Niveau 2 (-Sign)    — + Signature Authenticode (certificat X.509 CodeSigning)
      Niveau 3 (-Timestamp) — + Horodatage RFC 3161 via TSA publique (FreeTSA ou Sectigo)

    Mapping réglementaire :
      DORA Art. 9          → Intégrité des données (SHA-256)
      FINMA Circ. 2023/1 §38 → Traçabilité (journalisation + manifeste)
      CSSF 22/806 Ctrl 7   → Non-répudiation (signature X.509)
      ISO 27001 A.8.16     → Audit trail (fichiers .log)
      eIDAS / RFC 3161     → Horodatage certifié (niveau Premium)

.PARAMETER ScriptPath
    Chemin vers le script PowerShell IAM à exécuter.

.PARAMETER ScriptArgs
    Arguments à passer au script cible (hashtable).

.PARAMETER OutputPath
    Dossier de destination pour les livrables scellés.
    Défaut : .\Final_Audits

.PARAMETER Client
    Nom du client pour le manifeste JSON.
    Défaut : "[CLIENT]"

.PARAMETER Author
    Nom du consultant pour le manifeste JSON.
    Défaut : "Arnaud Montcho"

.PARAMETER Sign
    Active la signature numérique Authenticode (niveau 2).
    Requiert un certificat CodeSigning dans Cert:\CurrentUser\My

.PARAMETER Timestamp
    Active l'horodatage RFC 3161 via TSA publique (niveau 3).
    Peut être combiné avec -Sign ou utilisé seul.

.PARAMETER TsaUrl
    URL de la TSA (Time Stamping Authority).
    Défaut : https://freetsa.org/tsr (gratuite, publique)
    Alternative : http://timestamp.sectigo.com (Sectigo, recommandé en production)

.PARAMETER DryRun
    Mode test : affiche le plan d'exécution sans rien exécuter ni écrire.

.EXAMPLE
    # Niveau 1 — Hash uniquement
    .\Invoke-SecureAudit.ps1 -ScriptPath ".\scripts\audit-accounts.ps1" -Client "Banque XYZ"

.EXAMPLE
    # Niveau 2 — Hash + Signature
    .\Invoke-SecureAudit.ps1 -ScriptPath ".\scripts\run-audit.ps1" -Client "Assurance ABC" -Sign

.EXAMPLE
    # Niveau 3 — Hash + Signature + Horodatage RFC 3161
    .\Invoke-SecureAudit.ps1 -ScriptPath ".\scripts\generate-campaign.ps1" -Client "Banque FINMA" -Sign -Timestamp

.EXAMPLE
    # DryRun pour valider sans exécuter
    .\Invoke-SecureAudit.ps1 -ScriptPath ".\scripts\audit-orphaned.ps1" -Client "Test" -Sign -Timestamp -DryRun

.NOTES
    Auteur    : Arnaud Montcho — Consultant IAM/IGA
    Version   : 1.0
    Date      : 2026-03-26
    GitHub    : https://github.com/CrepuSkull/iam-evidence-sealer

    AVERTISSEMENT JURIDIQUE :
    Un certificat auto-signé (New-SelfSignedCertificate) garantit l'intégrité technique
    mais n'a PAS de valeur juridique reconnue par un tiers. Pour une valeur probante
    en contexte réglementaire (FINMA, CSSF), utilisez un certificat émis par une CA
    commerciale reconnue (Sectigo, DigiCert) COMBINÉ à l'horodatage RFC 3161 (-Timestamp).
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Chemin du script IAM à exécuter")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ScriptPath,

    [Parameter(Mandatory = $false)]
    [hashtable]$ScriptArgs = @{},

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Final_Audits",

    [Parameter(Mandatory = $false)]
    [string]$Client = "[CLIENT]",

    [Parameter(Mandatory = $false)]
    [string]$Author = "Arnaud Montcho",

    [Parameter(Mandatory = $false)]
    [switch]$Sign,

    [Parameter(Mandatory = $false)]
    [switch]$Timestamp,

    [Parameter(Mandatory = $false)]
    [string]$TsaUrl = "https://freetsa.org/tsr",

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────

$ScriptName    = [System.IO.Path]::GetFileName($ScriptPath)
$Timestamp_Now = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$RunId         = [System.Guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()
$LogFile       = Join-Path $OutputPath "Seal_${Timestamp_Now}_${RunId}.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $Line -ForegroundColor $(if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "Cyan" })
    if (-not $DryRun) { Add-Content -Path $LogFile -Value $Line -Encoding UTF8 }
}

function Write-Section {
    param([string]$Title)
    $Sep = "=" * 60
    Write-Log $Sep
    Write-Log "  $Title"
    Write-Log $Sep
}

# ─────────────────────────────────────────────
# DRYRUN — PLAN D'EXÉCUTION
# ─────────────────────────────────────────────

if ($DryRun) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║           DRYRUN — PLAN D'EXÉCUTION (SANS EFFET)        ║" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Script cible   : $ScriptPath" -ForegroundColor White
    Write-Host "  Client         : $Client" -ForegroundColor White
    Write-Host "  Auteur         : $Author" -ForegroundColor White
    Write-Host "  Dossier sortie : $OutputPath" -ForegroundColor White
    Write-Host ""
    Write-Host "  Niveau de preuve :" -ForegroundColor Yellow
    Write-Host "  [1] Hash SHA-256     → TOUJOURS actif" -ForegroundColor Green
    Write-Host "  [2] Signature X.509  → $(if ($Sign) { '✅ ACTIVÉ (-Sign)' } else { '⬜ désactivé' })" -ForegroundColor $(if ($Sign) { "Green" } else { "Gray" })
    Write-Host "  [3] Horodatage RFC 3161 → $(if ($Timestamp) { "✅ ACTIVÉ (-Timestamp) via $TsaUrl" } else { '⬜ désactivé' })" -ForegroundColor $(if ($Timestamp) { "Green" } else { "Gray" })
    Write-Host ""

    if ($Sign) {
        $Certs = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue
        if ($Certs) {
            Write-Host "  Certificat disponible : $($Certs[0].Subject) (exp. $($Certs[0].NotAfter.ToString('yyyy-MM-dd')))" -ForegroundColor Green
        } else {
            Write-Host "  ⚠  AUCUN certificat CodeSigning trouvé dans Cert:\CurrentUser\My" -ForegroundColor Red
            Write-Host "     → Exécutez New-SelfSignedCert.ps1 pour créer un certificat de test" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "  Livrables qui seraient générés :" -ForegroundColor Yellow
    Write-Host "  ├── <rapport>.csv            (sortie du script cible)" -ForegroundColor White
    Write-Host "  ├── <rapport>.sha256          (empreinte SHA-256)" -ForegroundColor White
    Write-Host "  ├── <rapport>.manifest        (métadonnées JSON)" -ForegroundColor White
    if ($Sign)      { Write-Host "  ├── <rapport>.p7s             (signature Authenticode)" -ForegroundColor White }
    if ($Timestamp) { Write-Host "  ├── <rapport>.tsr             (token RFC 3161)" -ForegroundColor White }
    Write-Host "  └── Seal_<date>_<id>.log     (journal d'exécution)" -ForegroundColor White
    Write-Host ""
    Write-Host "  → Relancez sans -DryRun pour exécuter." -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# ─────────────────────────────────────────────
# PRÉPARATION DOSSIER DE SORTIE
# ─────────────────────────────────────────────

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Section "INVOKE-SECUREAUDIT — DÉMARRAGE"
Write-Log "Script      : $ScriptName"
Write-Log "Client      : $Client"
Write-Log "Run ID      : $RunId"
Write-Log "Niveaux     : SHA-256=OUI | Sign=$($Sign.IsPresent) | RFC3161=$($Timestamp.IsPresent)"

# ─────────────────────────────────────────────
# ÉTAPE 1 — EXÉCUTION DU SCRIPT CIBLE
# ─────────────────────────────────────────────

Write-Section "ÉTAPE 1 — EXÉCUTION DU SCRIPT CIBLE"

$ReportFile = $null
$ExecStart  = Get-Date

try {
    Write-Log "Lancement : $ScriptPath"

    # Snapshot des fichiers avant exécution pour détecter les nouveaux rapports
    $FilesBefore = Get-ChildItem -Path (Split-Path $ScriptPath -Parent) -File -Recurse `
        -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName

    # Exécution
    if ($ScriptArgs.Count -gt 0) {
        & $ScriptPath @ScriptArgs
    } else {
        & $ScriptPath
    }

    $ExecEnd      = Get-Date
    $ExecDuration = ($ExecEnd - $ExecStart).TotalSeconds

    Write-Log "Exécution terminée en $([math]::Round($ExecDuration, 1)) secondes"

    # Détection du rapport généré (fichier le plus récent dans le répertoire du script)
    $FilesAfter = Get-ChildItem -Path (Split-Path $ScriptPath -Parent) -File -Recurse `
        -ErrorAction SilentlyContinue | Where-Object {
            $_.FullName -notin $FilesBefore -and
            $_.Extension -in @('.csv', '.json', '.md', '.txt', '.html', '.xml')
        } | Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($FilesAfter) {
        $ReportFile = $FilesAfter.FullName
        Write-Log "Rapport détecté : $($FilesAfter.Name)"
    } else {
        Write-Log "Aucun rapport détecté automatiquement — vérifiez le dossier de sortie du script cible" "WARN"
        # Fallback : chercher dans le dossier de sortie du sealer
        $Fallback = Get-ChildItem -Path $OutputPath -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($Fallback) {
            $ReportFile = $Fallback.FullName
            Write-Log "Fallback : utilisation de $($Fallback.Name)" "WARN"
        }
    }

} catch {
    Write-Log "ERREUR lors de l'exécution du script : $_" "ERROR"
    throw
}

if (-not $ReportFile -or -not (Test-Path $ReportFile)) {
    Write-Log "Impossible de localiser le rapport généré. Abandon." "ERROR"
    exit 1
}

# Copie vers le dossier de sortie sécurisé
$ReportBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ReportFile)
$ReportExt      = [System.IO.Path]::GetExtension($ReportFile)
$SealedName     = "${ReportBaseName}_${Timestamp_Now}${ReportExt}"
$SealedPath     = Join-Path $OutputPath $SealedName

Copy-Item -Path $ReportFile -Destination $SealedPath -Force
Write-Log "Rapport copié → $SealedPath"

# ─────────────────────────────────────────────
# ÉTAPE 2 — HASH SHA-256 (TOUJOURS ACTIF)
# ─────────────────────────────────────────────

Write-Section "ÉTAPE 2 — HASH SHA-256"

$HashResult  = Get-FileHash -Path $SealedPath -Algorithm SHA256
$HashValue   = $HashResult.Hash
$HashFile    = "${SealedPath}.sha256"

"$HashValue  $SealedName" | Out-File -FilePath $HashFile -Encoding UTF8

Write-Log "SHA-256 : $HashValue"
Write-Log "Fichier : $([System.IO.Path]::GetFileName($HashFile))"

# ─────────────────────────────────────────────
# ÉTAPE 3 — SIGNATURE AUTHENTICODE (OPTIONNEL)
# ─────────────────────────────────────────────

$SignatureStatus = "NOT_REQUESTED"

if ($Sign) {
    Write-Section "ÉTAPE 3 — SIGNATURE AUTHENTICODE (X.509)"

    $Certs = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Sort-Object NotAfter -Descending

    if (-not $Certs) {
        Write-Log "Aucun certificat CodeSigning trouvé dans Cert:\CurrentUser\My" "ERROR"
        Write-Log "→ Exécutez : .\New-SelfSignedCert.ps1 pour créer un certificat de test" "WARN"
        Write-Log "→ Pour une valeur réglementaire, utilisez un certificat CA commerciale" "WARN"
        $SignatureStatus = "ERROR_NO_CERT"
    } else {
        $Cert = $Certs[0]
        Write-Log "Certificat : $($Cert.Subject)"
        Write-Log "Émetteur   : $($Cert.Issuer)"
        Write-Log "Expiration : $($Cert.NotAfter.ToString('yyyy-MM-dd'))"

        # Avertissement certificat auto-signé
        if ($Cert.Issuer -eq $Cert.Subject) {
            Write-Log "AVERTISSEMENT : Certificat auto-signé — valeur technique uniquement, pas de valeur juridique" "WARN"
            Write-Log "→ Pour FINMA/CSSF, utilisez un certificat Sectigo ou DigiCert + -Timestamp" "WARN"
        }

        # Vérification expiration
        if ($Cert.NotAfter -lt (Get-Date)) {
            Write-Log "ERREUR : Certificat expiré le $($Cert.NotAfter.ToString('yyyy-MM-dd'))" "ERROR"
            $SignatureStatus = "ERROR_CERT_EXPIRED"
        } else {
            try {
                $SigResult = Set-AuthenticodeSignature -FilePath $SealedPath -Certificate $Cert
                if ($SigResult.Status -eq "Valid") {
                    Write-Log "Signature OK — Empreinte : $($Cert.Thumbprint)"
                    $SignatureStatus = "SIGNED"
                } else {
                    Write-Log "Signature échouée : $($SigResult.StatusMessage)" "ERROR"
                    $SignatureStatus = "ERROR_SIGN_FAILED"
                }
            } catch {
                Write-Log "Exception lors de la signature : $_" "ERROR"
                $SignatureStatus = "ERROR_EXCEPTION"
            }
        }
    }
} else {
    Write-Log "Signature Authenticode non demandée (ajouter -Sign pour activer)" "INFO"
}

# ─────────────────────────────────────────────
# ÉTAPE 4 — HORODATAGE RFC 3161 (OPTIONNEL)
# ─────────────────────────────────────────────

$TimestampStatus = "NOT_REQUESTED"

if ($Timestamp) {
    Write-Section "ÉTAPE 4 — HORODATAGE RFC 3161"
    Write-Log "TSA : $TsaUrl"
    Write-Log "NOTE : L'horodatage RFC 3161 ancre le hash dans une chaîne temporelle certifiée par un tiers"
    Write-Log "       C'est la preuve que le rapport existait tel quel à cette date/heure précise"

    $TsrFile = "${SealedPath}.tsr"

    try {
        # Vérification disponibilité OpenSSL ou certutil
        $OpenSSL  = Get-Command openssl -ErrorAction SilentlyContinue
        $CertUtil = Get-Command certutil -ErrorAction SilentlyContinue

        if ($OpenSSL) {
            # Méthode OpenSSL (cross-platform, recommandée)
            Write-Log "Méthode : OpenSSL"

            $TsqFile = "${SealedPath}.tsq"

            # Génération de la requête d'horodatage
            & openssl ts -query -data $SealedPath -no_nonce -sha256 -out $TsqFile 2>&1 | ForEach-Object { Write-Log "  openssl: $_" }

            if (Test-Path $TsqFile) {
                # Envoi à la TSA
                $WebClient = New-Object System.Net.WebClient
                $WebClient.Headers.Add("Content-Type", "application/timestamp-query")
                $TsqBytes = [System.IO.File]::ReadAllBytes($TsqFile)

                try {
                    $TsrBytes = $WebClient.UploadData($TsaUrl, "POST", $TsqBytes)
                    [System.IO.File]::WriteAllBytes($TsrFile, $TsrBytes)
                    Write-Log "Token RFC 3161 reçu → $([System.IO.Path]::GetFileName($TsrFile))"
                    $TimestampStatus = "TIMESTAMPED_OPENSSL"

                    # Vérification du token
                    & openssl ts -verify -data $SealedPath -in $TsrFile -CAfile <(openssl ts -reply -in $TsrFile -text 2>&1) 2>&1 | ForEach-Object { Write-Log "  verify: $_" }

                } catch {
                    Write-Log "Impossible de contacter la TSA : $_" "WARN"
                    Write-Log "→ Vérifiez la connexion ou essayez : http://timestamp.sectigo.com" "WARN"
                    $TimestampStatus = "ERROR_TSA_UNREACHABLE"
                } finally {
                    Remove-Item $TsqFile -ErrorAction SilentlyContinue
                }
            }

        } elseif ($CertUtil) {
            # Méthode certutil (Windows natif)
            Write-Log "Méthode : certutil (Windows natif)"
            Write-Log "NOTE : certutil ne supporte pas directement RFC 3161 pour fichiers arbitraires" "WARN"
            Write-Log "→ Pour un horodatage complet, installez OpenSSL : https://slproweb.com/products/Win32OpenSSL.html" "WARN"
            Write-Log "→ Alternative Windows : utiliser signtool.exe avec /tr et /td sha256 lors de la signature" "WARN"
            $TimestampStatus = "PARTIAL_NO_OPENSSL"

        } else {
            Write-Log "Ni OpenSSL ni certutil disponible" "WARN"
            Write-Log "→ Pour activer RFC 3161, installez OpenSSL et ajoutez-le au PATH" "WARN"
            Write-Log "→ Guide : https://wiki.openssl.org/index.php/Binaries" "WARN"
            $TimestampStatus = "ERROR_NO_TOOL"

            # Fallback : créer un fichier de métadonnées d'horodatage manuel
            $TsManual = @{
                Note    = "Horodatage manuel — OpenSSL non disponible"
                Date    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                SHA256  = $HashValue
                TSA_URL = $TsaUrl
                Action  = "Installer OpenSSL et relancer avec -Timestamp pour un horodatage certifié RFC 3161"
            }
            $TsManual | ConvertTo-Json -Depth 3 | Out-File -FilePath "${SealedPath}.ts_manual" -Encoding UTF8
            Write-Log "Fichier .ts_manual créé avec instructions de remédiation" "WARN"
        }

    } catch {
        Write-Log "Erreur lors de l'horodatage : $_" "ERROR"
        $TimestampStatus = "ERROR_EXCEPTION"
    }
} else {
    Write-Log "Horodatage RFC 3161 non demandé (ajouter -Timestamp pour activer)" "INFO"
}

# ─────────────────────────────────────────────
# ÉTAPE 5 — MANIFESTE JSON
# ─────────────────────────────────────────────

Write-Section "ÉTAPE 5 — MANIFESTE JSON"

$ProofLevel = "L1_HASH"
if ($Sign -and $SignatureStatus -eq "SIGNED") { $ProofLevel = "L2_SIGNED" }
if ($Timestamp -and $TimestampStatus -like "TIMESTAMPED*") { $ProofLevel = "L3_TIMESTAMPED" }

$Manifest = [ordered]@{
    "_schema"          = "iam-evidence-sealer/v1.0"
    "RunId"            = $RunId
    "Client"           = $Client
    "Author"           = $Author
    "Date"             = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    "Script"           = $ScriptName
    "Report"           = [System.IO.Path]::GetFileName($SealedPath)
    "SHA256"           = $HashValue
    "ProofLevel"       = $ProofLevel
    "Signed"           = ($SignatureStatus -eq "SIGNED")
    "SignatureStatus"  = $SignatureStatus
    "Timestamped"      = ($TimestampStatus -like "TIMESTAMPED*")
    "TimestampStatus"  = $TimestampStatus
    "TsaUrl"           = if ($Timestamp) { $TsaUrl } else { $null }
    "RegulatoryMapping" = [ordered]@{
        "DORA_Art9"         = "SHA-256 integrity"
        "FINMA_2023_1_S38"  = "Execution log + manifest"
        "CSSF_22806_Ctrl7"  = if ($SignatureStatus -eq "SIGNED") { "X.509 signature — COVERED" } else { "X.509 signature — NOT APPLIED" }
        "ISO27001_A816"     = "Execution log"
        "RFC3161_eIDAS"     = if ($TimestampStatus -like "TIMESTAMPED*") { "Certified timestamp — COVERED" } else { "Certified timestamp — NOT APPLIED" }
    }
}

$ManifestFile = "${SealedPath}.manifest"
$Manifest | ConvertTo-Json -Depth 5 | Out-File -FilePath $ManifestFile -Encoding UTF8

Write-Log "Manifeste : $([System.IO.Path]::GetFileName($ManifestFile))"
Write-Log "Niveau de preuve : $ProofLevel"

# ─────────────────────────────────────────────
# RÉSUMÉ FINAL
# ─────────────────────────────────────────────

Write-Section "RÉSUMÉ D'EXÉCUTION"

Write-Host ""
Write-Host "  ✅ Rapport      : $([System.IO.Path]::GetFileName($SealedPath))" -ForegroundColor Green
Write-Host "  ✅ SHA-256      : $HashValue" -ForegroundColor Green
Write-Host "  $(if ($SignatureStatus -eq 'SIGNED') {'✅'} elseif ($SignatureStatus -eq 'NOT_REQUESTED') {'⬜'} else {'❌'}) Signature   : $SignatureStatus" -ForegroundColor $(if ($SignatureStatus -eq "SIGNED") { "Green" } elseif ($SignatureStatus -eq "NOT_REQUESTED") { "Gray" } else { "Red" })
Write-Host "  $(if ($TimestampStatus -like 'TIMESTAMPED*') {'✅'} elseif ($TimestampStatus -eq 'NOT_REQUESTED') {'⬜'} else {'⚠ '}) RFC 3161    : $TimestampStatus" -ForegroundColor $(if ($TimestampStatus -like "TIMESTAMPED*") { "Green" } elseif ($TimestampStatus -eq "NOT_REQUESTED") { "Gray" } else { "Yellow" })
Write-Host "  ✅ Niveau       : $ProofLevel" -ForegroundColor Green
Write-Host "  ✅ Log          : $([System.IO.Path]::GetFileName($LogFile))" -ForegroundColor Green
Write-Host ""
Write-Log "Terminé — Dossier : $OutputPath"
