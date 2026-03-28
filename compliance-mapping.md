# Mapping réglementaire — IAM Evidence Sealer

> *Pour les auditeurs, RSSI et équipes de conformité réglementaire.*  
> Ce document établit la correspondance entre les contrôles techniques du module et les exigences réglementaires DORA, FINMA, CSSF et ISO 27001.

---

## DORA — Digital Operational Resilience Act (UE 2022/2554)

### Contexte
DORA s'applique aux entités financières de l'UE (banques, assurances, entreprises d'investissement) et à leurs prestataires TIC critiques. Entrée en application : 17 janvier 2025.

| Article DORA | Exigence | Couverture iam-evidence-sealer | Preuve |
|--------------|----------|-------------------------------|--------|
| Art. 9 §4(b) | Protection de l'intégrité des données, y compris contre la manipulation | Hash SHA-256 — toute modification post-génération est détectable | Fichier `.sha256` |
| Art. 9 §4(c) | Mesures permettant de détecter rapidement toute activité anormale | Log d'exécution horodaté | Fichier `.log` |
| Art. 12 §1 | Politiques de journalisation des systèmes | Journalisation complète de chaque exécution avec Run ID unique | Fichier `.log` |
| Art. 12 §3 | Conservation des journaux | Les livrables sont auto-archivés dans `Final_Audits/` avec nommage temporel | Dossier `Final_Audits/` |
| Art. 15 | Tests de résilience opérationnelle numérique | Mode `-DryRun` permet de tester le pipeline sans exécution réelle | Comportement `-DryRun` |

**Niveau minimum recommandé pour conformité DORA :** L2 (Hash + Signature avec certificat CA)

---

## FINMA — Circulaire 2023/1 (Risques opérationnels — banques)

### Contexte
La FINMA Circ. 2023/1 remplace la Circ. 2008/21 et renforce les exigences de gestion des risques opérationnels pour les établissements bancaires soumis à la FINMA (Suisse).

| Paragraphe | Exigence | Couverture | Preuve |
|-----------|----------|------------|--------|
| §32 | Identification et documentation des risques opérationnels | Manifeste JSON documente le contexte de chaque audit | Fichier `.manifest` |
| §38 | Traçabilité des opérations critiques sur les systèmes d'information | Log complet avec horodatage, identifiant d'exécution unique, nom du script | Fichier `.log` |
| §42 | Mesures techniques pour garantir l'intégrité des données de référence | Hash SHA-256 + signature X.509 | Fichiers `.sha256`, signature in-place |
| §51 | Conservation des preuves pour les contrôles internes et audits externes | Archivage systématique dans `Final_Audits/` | Dossier `Final_Audits/` |

**Note FINMA spécifique :** La FINMA accepte les preuves cryptographiques comme élément de la documentation de contrôle interne, à condition que la chaîne de preuve soit complète et vérifiable. Le niveau L3 (Hash + Signature CA + RFC 3161) est le standard recommandé pour les missions bancaires suisses.

**Niveau minimum recommandé pour conformité FINMA :** L3 (Hash + Signature CA commerciale + Horodatage RFC 3161)

---

## CSSF — Circulaire 22/806 (Gestion des risques TIC — Luxembourg)

### Contexte
La CSSF Circ. 22/806 transpose les orientations EBA/GL/2019/04 en droit luxembourgeois et s'applique aux établissements de crédit et entreprises d'investissement soumis à la CSSF.

| Contrôle | Domaine | Exigence | Couverture | Preuve |
|---------|---------|----------|------------|--------|
| Contrôle 7 | Gestion des identités et des accès | Non-répudiation des opérations sur les comptes | Signature X.509 Authenticode | Signature in-place |
| Contrôle 8 | Journalisation et surveillance | Logs d'activité IAM horodatés et conservés | Fichier `.log` avec Run ID | Fichier `.log` |
| Contrôle 12 | Gestion des incidents | Traçabilité des actions de remédiation | Manifeste JSON + log par exécution | `.manifest`, `.log` |
| Contrôle 15 | Tests et audit | Documentation des tests de conformité | Mode `-DryRun` + log de test | Fichier `.log` |

**Niveau minimum recommandé pour conformité CSSF :** L2-L3 selon criticité du livrable

---

## ISO 27001:2022

| Contrôle Annexe A | Domaine | Couverture |
|-------------------|---------|------------|
| A.8.16 | Surveillance des activités | Journalisation complète de chaque exécution |
| A.8.17 | Synchronisation des horloges | Horodatage systématique dans logs et manifestes |
| A.8.20 | Sécurité des réseaux | Sans objet (module offline) |
| A.5.33 | Protection des enregistrements | Archivage horodaté dans `Final_Audits/` |
| A.5.34 | Confidentialité | La clé privée ne quitte jamais le poste du consultant |

---

## Matrice de couverture synthétique

```
                        L1 Hash   L2 Signature   L3 RFC3161
                        SHA-256   X.509          Horodatage
                       ─────────  ─────────────  ──────────
DORA Art. 9 (intégrité)   ✅           ✅            ✅
DORA Art. 12 (logs)       ✅           ✅            ✅
FINMA §38 (traçabilité)   ✅           ✅            ✅
FINMA §42 (intégrité)     ✅           ✅            ✅
CSSF Ctrl 7 (non-répud.)  ⬜           ✅            ✅
CSSF Ctrl 8 (logs)        ✅           ✅            ✅
ISO 27001 A.8.16 (logs)   ✅           ✅            ✅
eIDAS Art.41 (timestamp)  ⬜           ⬜            ✅
```

---

## Questions fréquentes des auditeurs

**Q : Le hash SHA-256 seul suffit-il pour un audit FINMA ?**  
R : Non. Le hash prouve l'intégrité mais pas l'origine ni la date. Pour FINMA, le niveau L3 (certificat CA + RFC 3161) est requis pour une valeur probante complète.

**Q : Un certificat auto-signé est-il accepté par la CSSF ?**  
R : Non en principe. La CSSF exige que l'identité du signataire soit vérifiable par un tiers de confiance indépendant, ce qu'un certificat auto-signé ne garantit pas. Utiliser un certificat émis par une CA commerciale reconnue.

**Q : Comment vérifier un rapport sans outils spécialisés ?**  
R : En PowerShell natif : `Get-FileHash rapport.csv -Algorithm SHA256` puis comparer avec `rapport.csv.sha256`. La vérification de la signature : `Get-AuthenticodeSignature rapport.csv`. Aucun logiciel tiers n'est nécessaire pour les niveaux L1 et L2.

**Q : Les logs peuvent-ils être falsifiés après coup ?**  
R : Les logs sont produits en temps réel pendant l'exécution et ne sont pas réécrits. De plus, le hash du rapport est calculé immédiatement après sa génération. Toute tentative de modification du rapport après scellage serait détectée à la vérification. Pour une garantie absolue contre la falsification des logs eux-mêmes, la mise en place d'un SIEM avec ingestion des logs en temps réel serait l'étape complémentaire.

**Q : Que couvre exactement le manifeste JSON ?**  
R : Le manifeste documente : l'identité du client, l'auteur, la date/heure d'exécution, le nom du script lancé, le nom du rapport produit, le hash SHA-256, le niveau de preuve appliqué, et le statut de chaque couche (signature, horodatage). Il constitue le document de traçabilité de la mission.

---

*Pour l'explication technique des mécanismes, voir `integrity-methodology.md`.*  
*Pour les scripts, voir `Invoke-SecureAudit.ps1`, `New-SelfSignedCert.ps1`, `Verify-SealedReport.ps1`.*
