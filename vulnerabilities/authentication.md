# Authentication Vulnerabilities

## Les bases

Attaquer l'authentification revient à exploiter l'écart entre ce que le site croit vérifier et ce qu'il vérifie réellement. Trois surfaces distinctes, de robustesse souvent inégale :

- **Login principal** — password, MFA.
- **Fonctions annexes** — register, reset password, change password, « stay logged in ». Même surface d'attaque, presque toujours moins durcie.
- **Facteurs** — *something you know* (password), *have* (device/code), *are* (biométrie). Vérifier deux fois le même facteur (code par email) reste du single-factor.

Outils — Burp Intruder, le mode dépend de l'attaque :

| Mode          | Payload sets  | Usage                                                        |
|---------------|---------------|-------------------------------------------------------------|
| Sniper        | 1             | Un seul champ — brute-force password, énumération username   |
| Battering ram | 1             | Même payload injecté dans plusieurs positions                |
| Pitchfork     | n (parallèle) | Paires liées — credential stuffing `user:pass`               |
| Cluster bomb  | n (produit)   | Toutes les combinaisons — user × password                    |

- **Grep - Extract** : isoler l'élément qui diffère entre réponses (oracle d'énumération).
- **Grep - Match** : marquer les réponses contenant un marqueur (`Welcome`, `locked`).
- **Scripting** > Intruder dès qu'un token CSRF/session tourne à chaque requête.

## Recon (avant d'attaquer)

Trois questions à trancher **avant tout payload**. On part du signal observable — le différentiel de réponse — pas d'un catalogue de techniques.

**1. Oracle** — la réponse trahit-elle quelque chose ? Comparer systématiquement les 4 cas :

```text
username invalide + password bidon
username VALIDE   + password bidon      ← la paire clé
username invalide + password valide (inconnu)
username VALIDE   + password VALIDE
```

Ce qui diffère = ce qu'on exploite :

```text
message texte      "Invalid username" ≠ "Invalid password"        → énumération directe
status HTTP        200 vs 401/302                                 → énumération
temps de réponse   username valide → password réellement hashé → plus lent
détail subtil      espace final, point, casse                     → énumération "subtile"
lockout            "account locked" n'apparaît que si user valide → énumération via blocage
```

**2. Protection** — qu'est-ce qui limite le brute-force ? Détermine la technique.

```text
rate limit / block par IP   → bypass X-Forwarded-For
lockout par compte          → n'arrête pas le spraying/stuffing (1 essai/compte)
CAPTCHA après N             → ralentit, parfois absent au 1er essai
aucune                      → brute-force direct
```

**3. Flow** — mono ou multi-étape ? Chaque transition d'état est un point de bypass.

```text
password → page code MFA    → déjà "logged in" avant le code ? accéder direct aux pages protégées
cookie de state (verify=x)  → paramètre modifiable = code généré/vérifié pour un autre compte
stay-logged-in              → cookie déterministe = forgeable / brute-forçable hors ligne
```

## Énumération d'usernames

Objectif : réduire l'espace de recherche avant le brute-force password. Signal repéré en Recon 1, automatisé au Sniper + Grep-Extract.

- **Réponses différentes** — deux messages distincts selon la validité du username.
- **Réponses subtilement différentes** — même message à un détail près (espace final, ponctuation). Trier sur la longueur de réponse ou Grep-Extract, pas à l'œil.
- **Timing** — username valide → le password est réellement vérifié (hash) → réponse plus lente. Amplifier avec un password très long (plusieurs milliers de caractères) pour creuser l'écart. Pitchfork pour varier le username en gardant le long password.
- **Via lockout** — après N essais sur un username valide, `account locked` ; username invalide → message générique. Le blocage lui-même est l'oracle.

## Brute-force du mot de passe

Une fois le username confirmé :

- **Brute-force ciblé** — Sniper sur le champ password, liste de mots de passe.
- **Password spraying** — 1 password courant × N usernames. Contourne le lockout : chaque compte n'encaisse qu'un essai, on reste sous le seuil par compte.
- **Credential stuffing** — dictionnaire de paires `user:pass` volées (réutilisation inter-sites). Pitchfork. Une seule passe automatisée compromet potentiellement plusieurs comptes ; le lockout par compte n'y fait rien (1 essai/compte).

## Contournement des protections

- **Rate limit / block par IP** — le compteur est indexé sur l'IP perçue. Réinitialiser à chaque requête :

```text
X-Forwarded-For: 1.2.3.4      (incrémenter la valeur à chaque essai)
```

- **Lockout par compte** — contourné par le spraying (rester sous le seuil). Certains sites remettent le compteur à zéro sur un comportement « normal » intercalé (login réussi sur un autre compte).
- **Plusieurs credentials par requête** — si l'API accepte le password sous forme de tableau JSON, tester N passwords en une requête échappe au compteur par requête :

```json
{"username":"carlos","password":["p1","p2","p3", "..."]}
```

## MFA / 2FA

**1. Bypass par saut d'étape** — après le password, l'utilisateur est déjà en état « logged in » côté serveur avant le code. Tenter d'accéder directement à une page réservée aux connectés en sautant la page de code. Si la page ne vérifie pas la complétion du 2e facteur → bypass total.

**2. Logique cassée (usurpation)** — le code MFA est rattaché à un compte via un cookie/paramètre posé à l'étape 1. Générer un code pour son propre compte, puis changer la cible avant vérification :

```text
étape 1 : login avec SON compte      → cookie  verify=attacker  + code envoyé
étape 2 : modifier  verify=carlos    → le code (le sien) est validé contre carlos
```

**3. Brute-force du code** — code à 4 chiffres = 10 000 valeurs. Sans rate limit sur l'étape verify, brute-force exhaustif. Gérer le token session/CSRF qui change à chaque tentative (macro Burp ou script). Piège : certains sites invalident la session après X échecs → réauth à intercaler.

## Fonctions annexes

Même exigence de robustesse que le login principal, souvent négligée.

- **Stay-logged-in cookie** — souvent déterministe, ex. `base64(username + ':' + md5(password))`. Construction devinable → forger le cookie d'un autre user, ou brute-forcer/craquer hors ligne (pas de rate limit réseau). Un XSS qui vole ce cookie donne un craquage offline.
- **Password reset — logique cassée** — le token est valide mais le compte réinitialisé est porté par un paramètre modifiable :

```text
POST /reset      token=<valide>&username=carlos&new-password=...
```

- **Password reset poisoning** — le lien de reset est construit à partir du `Host` (ou `X-Forwarded-Host`). Injecter son domaine → la victime clique → le token fuit :

```text
Host: attacker.com      → lien = https://attacker.com/reset?token=<victime>
```

- **Change password** — canal de brute-force via le champ « current password », ou différentiel valide/invalide exploitable.

## Prévention

### Ne pas compter sur les utilisateurs

Imposer le comportement sûr plutôt que l'espérer. Vérificateur de force temps réel (ex. zxcvbn, Dropbox) plutôt que règles rigides que les utilisateurs contournent par des patterns prévisibles.

### Empêcher l'énumération

Messages d'erreur **identiques au caractère près**, même status HTTP, temps de réponse indistinguables quelle que soit la validité du username. Un seul détail divergent suffit à l'oracle.

### Brute-force protection robuste

Rate limiting strict par IP, résistant à la manipulation (ne pas faire confiance à `X-Forwarded-For`). CAPTCHA au-delà d'un seuil. But réaliste : rendre l'attaque assez pénible pour qu'elle parte chercher une cible plus molle.

### Auditer la logique de vérification

Un contrôle contournable ne vaut guère mieux que pas de contrôle. Vérifier qu'aucune page protégée n'est atteignable sans complétion de toutes les étapes, et qu'aucun paramètre client ne porte l'identité du compte vérifié.

### Vrai MFA

Deux facteurs de nature différente. Code par email = single-factor déguisé. SMS = faible (SIM swapping). Idéal : app/dispositif dédié générant le code. Logique de vérification aussi solide que le login principal.