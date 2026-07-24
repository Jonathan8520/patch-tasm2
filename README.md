# Patch TASM2 — bypass serveurs Gameloft

Automatise le patch de **The Amazing Spider-Man 2 (1.3.1, iOS)** pour
neutraliser les appels aux serveurs Gameloft morts et forcer le mode
offline, ce qui debloque la sauvegarde locale.

## Le probleme

Le jeu reste bloque sur « downloading profile » : il appelle
`livewebapp.gameloft.com/scripts/autologin.php` au lancement. Le serveur
n'existe plus, la requete part en timeout et l'init du profil ne se
termine jamais.

Erreurs internes du binaire :
- `[COnlineManager] anubi server init profile failed`
- `[CFedServerManager::GetProfile] Failed to get profile info from Seshat`

Un chemin offline existe pourtant dans le code
(`OfflineItems initialized with the default game config`), mais il ne se
declenche que sur **echec net**, pas sur timeout.

## Le patch

### Patch principal (issu du desassemblage arm64)

Le blocage sur « Telechargement du profil » est un ecran nomme
`UI_DOWNLOADING_PROFILE`. Le desassemblage montre qu'il n'a **qu'un seul
site d'emission** dans tout le binaire : dans la boucle d'update, un
predicat partage (`sub_100346c10`, "faut-il telecharger le profil ?")
decide entre afficher ce spinner ou emettre l'etat natif `UI_FIRST_CHECK`
(« pas de profil a telecharger, on continue ») :

```
bl   sub_100346c10        ; predicat "download profile ?"
cbz  w0, UI_FIRST_CHECK    ; ==0 -> on continue
...  UI_DOWNLOADING_PROFILE ; !=0 -> spinner infini (serveur mort)
```

Le predicat renvoie « oui » tant que le login en ligne est actif, mais le
serveur Gameloft est mort : il ne se termine jamais, donc le spinner reste.
Le patch remplace ce `bl` (au **seul** site concerne, pas la fonction
partagee appelee ~50 fois ailleurs) par `mov w0, #0`. Le `cbz` est alors
toujours pris : le jeu route vers `UI_FIRST_CHECK` et poursuit hors-ligne.
4 octets, longueur preservee. Auto-localise via la reference unique a la
chaine, donc robuste.

### Patch sauvegarde locale (autosave progression)

La progression est ecrite dans `ud_Spider2.sav` par un autosave, mais
seulement si un flag "dirty" (`saveMgr+0xfa8`) est pose. Ce flag n'etait
committe qu'au travers du profil serveur : hors-ligne il ne l'est plus,
donc la progression n'etait plus sauvegardee (le fichier existe mais reste
fige). Le writer saute alors serialisation **et** ecriture :

```
ldr  x8, [x19, #0xfa8]    ; flag dirty
and  w9, w8, #0xff
cbz  w9, <skip tout>      ; dirty==0 -> rien n'est ecrit
```

Le patch remplace ce `cbz` par `nop` : l'autosave ecrit la progression
courante a chaque cycle (~20 s), independamment du flag. 4 octets, longueur
preservee, auto-localise via la chaine `%s/ud_Spider2.sav`.

### Patchs complementaires

Les hostnames Gameloft morts sont remplaces par des noms en `.invalid`
(RFC 6761 : ne resolvent jamais), plus la neutralisation des chemins et de
la fonction de detection jailbreak — tout a longueur strictement preservee,
aucun offset du Mach-O n'est decale.

| Host neutralise            | Role                        |
|----------------------------|-----------------------------|
| livewebapp.gameloft.com    | autologin.php (bloqueur #1) |
| eve.gameloft.com           | services profil             |
| pjsmmm-legacy.gameloft.com | backend legacy              |
| ingameads.gameloft.com     | pub / iphoneloading.php     |
| 201205igp.gameloft.com     | IGP / freemium              |

## Le binaire

- FAT `armv7 + arm64` → compatible iPhone moderne
- `cryptid=0` sur les deux slices → **deja dechiffre**, pas de prompt Apple ID
- SDK iphoneos10.3 / Xcode 8.3 (build 2017), MinimumOSVersion 8.0
- SHA1 original : `b3d322a788bbeeb1a006ba0da23a28300a5b7105`
- Taille : 33 375 152 octets (inchangee apres patch)
- Sauvegarde locale : `ud_Spider2.sav` (userdata / skill / goods / SaveIndex)

## Usage

1. Pousser ce repo sur GitHub
2. Onglet **Actions** → *Patch TASM2 IPA* → **Run workflow**
3. A la fin du run, l'IPA patchee est publiee dans une **Release GitHub**
   (section *Releases* du repo), attachee sous le tag choisi
   (`patched-latest` par defaut). Telecharger `SpiderMan2_patched.ipa`.
4. Installer via LiveContainer / SideStore / Sideloadly

## Important : ne pas patcher apres installation

LiveContainer charge les apps avec `dlopen()` et convertit le binaire de
`MH_EXECUTE` vers `MH_DYLIB` **au moment de l'installation**. Remplacer le
binaire dans un `.app` deja installe ecrase cette conversion et produit :

```
cannot dlopen a main executable
```

Il faut donc patcher **l'IPA avant installation** et laisser LiveContainer
faire la conversion sur le binaire patche.

## Pourquoi une Release et pas un artifact

L'IPA fait ~769 Mo. Les artifacts Actions sont limites par le quota de
stockage (500 Mo sur les comptes perso), ce qui fait echouer l'upload d'un
gros fichier. Une **Release GitHub** accepte des fichiers jusqu'a 2 Go et
n'est pas comptee dans ce quota — le workflow y publie donc directement
l'IPA.

## Alternative sans patch — a essayer d'abord

Bloquer ces domaines via DNS (NextDNS, AdGuard, DNS manuel) **avant le
premier lancement**. Un NXDOMAIN produit le meme echec net que le patch,
sans manipulation de fichier et de facon reversible.

## Statut

Le patch repose sur une analyse **statique** du binaire. Les domaines et
le fallback offline sont confirmes dans le code, mais rien n'a ete execute :
que le fallback se declenche reellement sur echec DNS reste a verifier sur
appareil.

Si le jeu boucle toujours apres patch, le blocage est plus profond que la
couche hostname et il faudra patcher le flot de controle autour de
`COnlineManager`.
