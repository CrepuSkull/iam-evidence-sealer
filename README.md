# iam-evidence-sealer

> **Protocole de scellage numérique pour rapports d'audit IAM**  
> *Chaque livrable devient une preuve inattaquable en contexte réglementaire.*

---

## Pourquoi ce module existe

Un rapport d'audit CSV généré par un script PowerShell peut être modifié après livraison — par accident, par erreur, ou de façon intentionnelle. Un auditeur FINMA, CSSF ou DORA qui reçoit un fichier n'a aucun moyen de savoir si ce fichier est identique à ce qui a été produit lors de l'analyse.

`iam-evidence-sealer` résout ce problème en trois niveaux de preuve progressifs :

| Niveau | Technologie | Garantit | Usage recommandé |
|--------|-------------|----------|------------------|
| **L1** | Hash SHA-256 | Intégrité — le fichier n'a pas changé | Tous les livrables |
| **L2** | Signature X.509 Authenticode | Authenticité — identifie le signataire | Rapports clients, clôture de mission |
| **L3** | Horodatage RFC 3161 | Antériorité — le rapport existait avant telle date | Rapports réglementaires FINMA/CSSF |

---

## Installation

Aucune installation requise. Les scripts sont autonomes, PowerShell 5.1+ natif Windows.

Pour l'horodatage RFC 3161 (niveau L3), OpenSSL doit être dans le PATH :
- Windows : [https://slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)
- Linux/Mac : inclus nativement

```powershell
# Cloner ou télécharger le repo
git clone https://github.com/CrepuSkull/iam-evidence-sealer.git
cd iam-evidence-sealer
```

---

## Démarrage rapide

### Étape 0 — Créer un certificat de test (première fois uniquement)

```powershell
.\New-SelfSignedCert.ps1
```

### Étape 1 — Valider sans exécuter (DryRun)

```powershell
.\Invoke-SecureAudit.ps1 `
    -ScriptPath "..\iam-foundation-lab\scripts\audit-accounts.ps1" `
    -Client "Banque XYZ" `
    -Sign -Timestamp `
    -DryRun
```

### Étape 2 — Exécuter avec scellage complet

```powershell
# Niveau L1 — Hash uniquement
.\Invoke-SecureAudit.ps1 -ScriptPath ".\scripts\audit-accounts.ps1" -Client "Client A"

# Niveau L2 — Hash + Signature
.\Invoke-SecureAudit.ps1 -ScriptPath ".\scripts\run-audit.ps1" -Client "Client B" -Sign

# Niveau L3 — Hash + Signature + Horodatage RFC 3161
.\Invoke-SecureAudit.ps1 -ScriptPath ".\scripts\generate-campaign.ps1" -Client "Banque FINMA" -Sign -Timestamp
```

### Étape 3 — Vérifier un rapport reçu

```powershell
.\Verify-SealedReport.ps1 -ReportPath ".\Final_Audits\Rapport_Audit_AD_2026-03-26.csv"
```

---

## Structure des livrables

Pour chaque rapport généré, le dossier `Final_Audits/` contient :

```
Final_Audits/
├── Rapport_Audit_AD_2026-03-26_143215.csv          ← Rapport
├── Rapport_Audit_AD_2026-03-26_143215.csv.sha256   ← Empreinte SHA-256
├── Rapport_Audit_AD_2026-03-26_143215.csv.manifest ← Manifeste JSON
├── Rapport_Audit_AD_2026-03-26_143215.csv.tsr      ← Token RFC 3161 (si -Timestamp)
└── Seal_2026-03-26_143215_A3F8C2D1.log             ← Journal d'exécution
```

### Format du manifeste JSON

```json
{
  "_schema": "iam-evidence-sealer/v1.0",
  "RunId": "A3F8C2D1",
  "Client": "Banque XYZ",
  "Author": "Arnaud Montcho",
  "Date": "2026-03-26 14:32:15",
  "Script": "audit-accounts.ps1",
  "Report": "Rapport_Audit_AD_2026-03-26_143215.csv",
  "SHA256": "a3f2b8c9d4e5f6...",
  "ProofLevel": "L3_TIMESTAMPED",
  "Signed": true,
  "Timestamped": true,
  "RegulatoryMapping": {
    "DORA_Art9": "SHA-256 integrity",
    "FINMA_2023_1_S38": "Execution log + manifest",
    "CSSF_22806_Ctrl7": "X.509 signature — COVERED",
    "ISO27001_A816": "Execution log",
    "RFC3161_eIDAS": "Certified timestamp — COVERED"
  }
}
```

---

## Mapping réglementaire

| Exigence réglementaire | Couverture | Fichier de preuve |
|------------------------|------------|-------------------|
| DORA Art. 9 — Intégrité des données | Hash SHA-256 | `.sha256` |
| FINMA Circ. 2023/1 §38 — Traçabilité | Logs + manifeste | `.manifest`, `.log` |
| CSSF 22/806 Contrôle 7 — Non-répudiation | Signature X.509 | Fichier signé in-place |
| ISO 27001 A.8.16 — Audit trail | Journalisation | `.log` |
| eIDAS / RFC 3161 — Horodatage certifié | Token TSA tiers | `.tsr` |

---

## Niveaux de preuve — Guide de décision

```
┌─────────────────────────────────────────────────────────┐
│ Quel niveau choisir ?                                   │
│                                                         │
│  Mission France, audit interne, démo client ?           │
│  → L1 (Hash SHA-256) — Suffisant                        │
│                                                         │
│  Clôture de mission, rapport client final ?             │
│  → L2 (+ Signature) avec certificat CA commercial      │
│                                                         │
│  Rapport destiné à FINMA, CSSF, ou régulateur ?        │
│  → L3 (+ RFC 3161) — Obligatoire pour valeur probante   │
│                                                         │
│  ⚠  Certificat auto-signé = L2 technique uniquement    │
│     Sans valeur juridique tierce reconnue              │
└─────────────────────────────────────────────────────────┘
```

---

## Intégration avec les autres repos

Ce module s'intègre comme wrapper universel des 3 repos IAM existants :

```
iam-foundation-lab/        → audit-accounts.ps1, audit-admins.ps1
IAM-Lab-Identity-Lifecycle/ → joiner.ps1, mover.ps1, leaver.ps1, audit-orphaned.ps1
iam-governance-lab/        → run-audit.ps1, generate-campaign.ps1, disable-inactive.ps1
      ↑
      └─── Tous enveloppables par Invoke-SecureAudit.ps1
```

Aucune modification des scripts existants n'est nécessaire.

---

## Sécurité — Ce qu'il ne faut JAMAIS faire

- ❌ Ne committez jamais votre fichier `.pfx` (clé privée) sur GitHub
- ❌ Ne committez jamais votre clé privée sous quelque forme que ce soit
- ✅ Ajoutez `*.pfx`, `*.key`, `*.p12` à votre `.gitignore`
- ✅ Renouveler le certificat avant expiration (rappel calendrier recommandé)

---

## Auteur

**Arnaud Montcho** — Consultant IAM/IGA Indépendant  
Spécialisation : Gouvernance des Identités & Conformité Réglementaire (FINMA · CSSF · DORA)  
GitHub : [CrepuSkull](https://github.com/CrepuSkull)

Faisant partie de l'écosystème **IAM-Lab** :
- [iam-foundation-lab](https://github.com/CrepuSkull/iam-foundation-lab) — Audit AD → Migration Entra ID
- [IAM-Lab-Identity-Lifecycle](https://github.com/CrepuSkull/IAM-Lab-Identity-Lifecycle) — Automatisation JML
- [iam-governance-lab](https://github.com/CrepuSkull/iam-governance-lab) — Contrôle continu & Recertification
- **iam-evidence-sealer** — Intégrité des preuves d'audit ← *vous êtes ici*

---

*Voir `docs/integrity-methodology.md` pour l'explication technique détaillée.*  
*Voir `docs/compliance-mapping.md` pour le mapping réglementaire complet.*
