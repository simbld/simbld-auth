# Guide de Migration de la Base de Données

## Introduction

Ce guide explique comment gérer les migrations de la base de données simbld-auth, à la fois avec la méthode
automatisée (via sqlx) et la méthode manuelle (via psql).

## Migrations automatisées (sqlx)

Notre application utilise `sqlx` pour les migrations automatisées. Les migrations sont définies dans le dossier
`/migrations` et sont exécutées automatiquement au démarrage de l'application via la fonction `run_migration` dans
`main.rs`.

### Comment fonctionnent les migrations automatisées

1. Les fichiers de migration suivent le format `XXXX_description.up.sql` et `XXXX_description.down.sql`
2. Au démarrage de l'application, `sqlx::migrate!()` exécute les migrations non appliquées dans l'ordre
3. sqlx maintient une table `_sqlx_migrations` pour suivre quelles migrations ont été appliquées

## Migrations manuelles

Pour exécuter manuellement les migrations (par exemple, pour le débogage ou les environnements spéciaux) :

1. Connectez-vous à la base de données :
   ```bash
   psql -U simbld -h localhost -p 5434 -d simbld_auth
   ```

2. Exécutez les migrations individuellement :
   ```sql
   \i migrations/0001_create-users.up.sql
   \i migrations/0002_create_roles.up.sql
   -- etc.
   ```

3. Ou utilisez le script `run_migrations.sh` :
   ```bash
   ./migrations/run_migrations.sh up 1 11
   ```

## Bonnes pratiques pour les migrations

1. **Toujours créer des scripts down** - Chaque migration doit avoir un script d'annulation correspondant
2. **Migrations idempotentes** - Utilisez `IF NOT EXISTS` ou `CREATE OR REPLACE` lorsque possible
3. **Tester les migrations** - Testez les scripts up et down avant de les appliquer en production
4. **Maintenir l'ordre** - Ne modifiez jamais une migration existante, créez-en une nouvelle
5. **Documentation** - Commentez les migrations complexes

## Résolution des problèmes courants

### Conflit de migration

Si une migration automatique échoue avec une erreur indiquant que la table existe déjà :

1. Vérifiez l'état des migrations dans la table `_sqlx_migrations`
2. Créez une nouvelle migration pour corriger le problème plutôt que de modifier une migration existante

### Vérification de cohérence

Utilisez le script `check_consistency.sql` pour vérifier l'état de votre base de données :

```bash
psql -U simbld -h localhost -p 5434 -d simbld_auth -f migrations/check_consistency.sql
```

## Mise à jour de la version du schéma

Après l'application d'une migration manuelle, mettez à jour la table `schema_versions` :

```sql
SELECT record_schema_version(11, 'Update users table password security', '0011_update_users_table_password_security.up.sql', CURRENT_USER);
```
