# Méthodologie d'intégrité des preuves d'audit

> *Pour les RSSI, auditeurs et équipes de conformité.*  
> Ce document explique comment fonctionne le protocole de scellage et pourquoi chaque niveau de preuve correspond à une exigence réglementaire spécifique.

---

## Le problème : un fichier sans preuve d'intégrité est une affirmation

Quand un consultant livre un fichier `rapport_audit.csv`, le client reçoit un fichier texte. Il n'a aucun moyen de vérifier :

- Que ce fichier est identique à celui produit lors de l'analyse
- Que personne n'a ajouté, supprimé ou modifié des lignes entre la production et la livraison
- Que ce fichier a bien été produit par ce consultant à cette date

Dans un contexte réglementaire (contrôle FINMA, examen CSSF, audit DORA), cette incertitude est un risque : si un auditeur remet en cause l'intégrité d'une preuve, la conformité entière de la mission peut être invalidée.

---

## La solution : trois couches de preuve cumulatives

### Couche 1 — Hash SHA-256 (intégrité)

**Ce que c'est :** Une empreinte numérique unique du fichier. Si un seul caractère change dans le fichier, l'empreinte change complètement.

**Comment ça marche :**
```
Fichier original → algorithme SHA-256 → empreinte de 64 caractères hexadécimaux
```

**Ce que ça prouve :** Le fichier `rapport.csv` que vous avez reçu est **bit pour bit identique** au fichier qui a produit l'empreinte `a3f2b8c9...`.

**Ce que ça ne prouve pas :** Qui a produit ce fichier, ni quand exactement.

**Vérification en une ligne PowerShell :**
```powershell
Get-FileHash rapport.csv -Algorithm SHA256
# Comparer avec le contenu de rapport.csv.sha256
```

**Mapping réglementaire :** DORA Art. 9 — exigences d'intégrité des données.

---

### Couche 2 — Signature numérique X.509 Authenticode (authenticité)

**Ce que c'est :** Une signature cryptographique apposée sur le fichier avec un certificat qui identifie le signataire.

**Comment ça marche :**
```
Fichier + Clé privée du consultant → Signature (fichier modifié in-place)
  → Le destinataire vérifie avec la clé publique du certificat
```

**Ce que ça prouve :** Ce fichier a été signé par le détenteur du certificat `CN=Arnaud Montcho`. Si le fichier est modifié après signature, la vérification échoue avec le statut `HashMismatch`.

**Distinction critique — certificat auto-signé vs certificat CA :**

| Type | Garantit | Ne garantit pas | Usage |
|------|----------|-----------------|-------|
| Auto-signé (`New-SelfSignedCertificate`) | Intégrité technique | Identité vérifiée par un tiers | Tests, démos, GitHub |
| CA commerciale (Sectigo, DigiCert) | Intégrité + identité vérifiée | — | Clients, régulateurs |

> ⚠ **Point critique :** Un certificat auto-signé ne peut pas servir de preuve juridique car n'importe qui peut créer un certificat au nom de n'importe qui. Seul un certificat émis par une CA reconnue (qui vérifie l'identité du demandeur) a une valeur probante.

**Vérification en PowerShell :**
```powershell
Get-AuthenticodeSignature rapport.csv
# Statut attendu : Valid
```

**Mapping réglementaire :** CSSF 22/806 Contrôle 7 — non-répudiation.

---

### Couche 3 — Horodatage RFC 3161 (antériorité certifiée)

**Ce que c'est :** Un horodatage émis par une autorité tierce de confiance (TSA — Time Stamping Authority) qui certifie qu'un fichier existait avant un instant précis.

**Comment ça marche :**
```
Hash du fichier → envoyé à la TSA (tiers indépendant)
  → TSA signe le hash avec son certificat + date/heure précise
  → Token .tsr retourné (preuve cryptographique de l'horodatage)
```

**Ce que ça prouve :** Le fichier `rapport.csv` avec ce hash précis existait **avant** la date inscrite dans le token, certifiée par un tiers indépendant (FreeTSA, Sectigo, etc.).

**Pourquoi c'est critique pour FINMA/CSSF :**
Sans RFC 3161, la date dans le manifeste JSON n'est qu'une affirmation du consultant. Avec RFC 3161, la date est certifiée par un tiers indépendant que ni le consultant ni le client ne contrôlent.

**Différence avec une simple signature horodatée :**
Une signature Authenticode peut inclure un horodatage du signataire lui-même (non certifié). RFC 3161 implique obligatoirement un tiers de confiance externe.

**Vérification avec OpenSSL :**
```bash
openssl ts -verify -data rapport.csv -in rapport.csv.tsr
# Résultat attendu : Verification: OK
```

**Mapping réglementaire :** eIDAS Règlement UE 910/2014 Art. 41, FINMA Circ. 2023/1 §38.

---

## Chaîne de preuve complète (niveau L3)

```
GÉNÉRATION                    LIVRAISON                    VÉRIFICATION
──────────                    ─────────                    ────────────
Script PS1 → rapport.csv
     │
     ├→ SHA-256 hash          → rapport.csv.sha256    →  Get-FileHash
     │
     ├→ Signature X.509       → (in-place dans CSV)   →  Get-AuthenticodeSignature
     │
     ├→ Token RFC 3161        → rapport.csv.tsr       →  openssl ts -verify
     │
     └→ Manifeste JSON        → rapport.csv.manifest  →  lecture + cross-check
```

N'importe quel auditeur peut reconstruire et vérifier cette chaîne de preuve de façon autonome, sans outil propriétaire, avec des commandes natives PowerShell et OpenSSL.

---

## Limites et honnêteté intellectuelle

Ce protocole **ne garantit pas** :

- La **pertinence métier** du rapport (les données analysées peuvent être incomplètes ou mal interprétées — c'est le rôle de la revue humaine)
- La **légalité** de l'opération (la signature certifie l'intégrité, pas la licéité du contenu)
- La **disponibilité future** des TSA publiques gratuites (FreeTSA) — pour des missions critiques, utiliser Sectigo ou une TSA institutionnelle

Ce protocole **garantit** :

- Que le fichier livré est identique à celui produit
- Que personne ne l'a modifié entre production et livraison
- Que l'identité du signataire est vérifiable (avec certificat CA)
- Que la date de production est certifiée par un tiers (avec RFC 3161)

---

## Recommandations par contexte de mission

| Contexte | Niveau recommandé | Certificat | TSA |
|----------|------------------|------------|-----|
| Démo, test, GitHub | L1 (Hash) | Auto-signé acceptable | Non requis |
| Mission France, audit interne | L1-L2 | CA commerciale | Facultatif |
| Clôture de mission client | L2 | CA commerciale | Recommandé |
| Rapport FINMA | L3 | CA commerciale reconnue CH | Sectigo recommandé |
| Rapport CSSF/DORA | L3 | CA commerciale reconnue UE | Sectigo ou TSA nationale |

---

*Pour le détail du mapping réglementaire référentiel par référentiel, voir `compliance-mapping.md`.*
