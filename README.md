# Patch TASM2 — bypass serveurs Gameloft

Automatise le patch de **The Amazing Spider-Man 2 (1.3.1, iOS)** pour
neutraliser les appels aux serveurs Gameloft morts et permettre de lancer
et jouer au jeu hors-ligne.

**Portee** : le jeu se lance et se joue. La progression de l'histoire n'est
en revanche **pas conservee** entre deux lancements — voir la section
« Sauvegarde locale : impossible par patch », conclusions verifiees sur
appareil.

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

### Sauvegarde locale : impossible par patch (conclusions, testees sur appareil)

Trois tentatives, toutes infirmees par des tests reels. Resume pour ne pas
les refaire :

**v1 — forcer l'autosave** (`nop` du gate "dirty" du writer). Regression :
blocage a 45 % au chargement. Le writer ecrit les `ud_*.sav` **sans throttle**
(seul `ud_Spider2.sav` a un timer 20 s) ; sans le gate il tourne a chaque
frame -> tempete d'I/O. La branche "skip" supprimee etait en plus le
**re-armement** du flag `+0xfa9`, ce qui bloquait definitivement le mark-dirty.

**v2 — forcer le flag dirty au flush evenementiel.** Fonctionne pour
l'ecriture (fichier bien mis a jour), mais sans effet : rien ne relit la
progression.

**v3 — persister les 17 objets** (`nop` du filtre `ldrb [x22,#0x25]`).
Aucun fichier supplementaire n'apparait : ce drapeau n'est pas le verrou.

**Pourquoi c'est un mur.** `ud_Spider2.sav` est du **code mort**. Son writer
fait :

```
sprintf(buf, "%s/ud_Spider2.sav", docs)   ; buf recoit le CHEMIN
fopen(...) ; rand()                        ; cle aleatoire, jamais stockee
XOR(buf, key ^ index) ; fwrite(buf, 0x7bf) ; on ecrit ce meme buf
```

Verifie sur un fichier reel de 1983 octets recupere sur appareil : avec la
cle deduite (`0xff`), le contenu dechiffre commence par
`/var/mobile/Containers/Data/Application/<UUID>/Documents/...` — le chemin
lui-meme — puis 47 % de zeros et des restes de pile. **Aucune donnee de jeu.**
Et la chaine `%s/ud_Spider2.sav` n'est referencee qu'une fois dans tout le
binaire : par ce writer. Aucun lecteur n'existe.

La vraie persistance locale (`ud_<Nom>.sav`, lecture `0x100211a2c` / ecriture
`0x1002115f0`, symetriques) ne couvre que **Sound, Control, InitPos, Economy,
Item, FriendList** — reglages et inventaire. La progression de l'histoire
n'y figure pas : elle vivait dans le profil serveur, ce que le jeu affiche
lui-meme (« Connecte-toi en ligne juste une fois pour recuperer ta derniere
sauvegarde »).

Conclusion : restaurer la progression demanderait d'**ecrire** un systeme de
sauvegarde (serialisation + deserialisation injectees dans le binaire), pas
de deverrouiller du code existant. Hors de portee d'un patch d'octets.

## Le binaire

- FAT `armv7 + arm64` → compatible iPhone moderne
- `cryptid=0` sur les deux slices → **deja dechiffre**, pas de prompt Apple ID
- SDK iphoneos10.3 / Xcode 8.3 (build 2017), MinimumOSVersion 8.0
- SHA1 original : `b3d322a788bbeeb1a006ba0da23a28300a5b7105`
- Taille : 33 375 152 octets (inchangee apres patch)
- `ud_Spider2.sav` : **code mort** (buffer de pile brouille par `rand()`, jamais relu)
- Persistance locale reelle : `ud_<Nom>.sav` — reglages et inventaire uniquement

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

**Verifie sur appareil** (LiveContainer, iOS) :
- le blocage sur « Telechargement du profil » est leve, le jeu se lance et
  se joue hors-ligne ;
- la progression n'est pas conservee entre deux lancements, et ce n'est pas
  un verrou a contourner : le code de sauvegarde de la progression locale
  n'existe pas dans ce binaire.

Les patchs hosts/jailbreak sont conserves ; seul le patch profil est
necessaire au deblocage.
