# Migration Guide: Inji Certify 0.11.0 → 0.12.0

This guide details the steps required to manually migrate your Inji Certify deployment from version **0.11.0** to **0.12.0**.

---

## 1. Database Upgrade

1. **Backup your database** before proceeding with any upgrade steps.
2. Navigate to the `db_upgrade_script` directory:
   ```sh
   cd db_upgrade_script
   ```
3. Review and configure the properties file as per your environment. Ensure all required values are set. Below is a sample `upgrade.properties` configuration:

   ```properties
   ACTION=upgrade
   MOSIP_DB_NAME=inji_certify
   DB_SERVERIP=127.0.0.1
   DB_PORT=5432
   SU_USER=postgres
   SU_USER_PWD=admin
   DEFAULT_DB_NAME=inji_certify
   CURRENT_VERSION=0.11.0
   UPGRADE_VERSION=0.12.0
   ```
   > **Note:** Ensure the `upgrade.properties` file is present in the same directory as the script, or provide the full path when running the script.

4. Run the upgrade shell script, passing the properties file as an argument:
   ```sh
   ./upgrade.sh upgrade.properties
   ```
   - This script will:
     - Apply database schema and data changes required for 0.12.0
   - Follow on-screen prompts and warnings. 
   - On successful completion, the script will log the upgrade status and any errors encountered.

5. To rollback the upgrade, update the `ACTION` property in your `upgrade.properties` file to `rollback` and re-run the script with the properties file as an argument:
   ```properties
   ACTION=rollback
   MOSIP_DB_NAME=inji_certify
   DB_SERVERIP=127.0.0.1
   DB_PORT=5432
   SU_USER=postgres
   SU_USER_PWD=admin
   DEFAULT_DB_NAME=inji_certify
   CURRENT_VERSION=0.11.0
   UPGRADE_VERSION=0.12.0
   ```
   Then execute:
   ```sh
   ./upgrade.sh upgrade.properties
   ```
   - This will attempt to revert the database changes applied during the upgrade. 
   - On successful completion, the script will log the rollback status and any errors encountered.

---

## 2. Configuration Updates

### Newly Added Configuration Properties

| Property Name                                                           | Required/Optional | Description |
|------------------------------------------------------------------------|-------------------|-------------|
| mosip.kernel.keymanager.signature.kid.prepend                          | Optional          | Prepend value for signature key IDs. |
| mosip.certify.credential-config.proof-types-supported                  | Required          | Supported proof types for credential configuration. |
| mosip.certify.credential-config.cryptographic-binding-methods-supported| Required          | Supported cryptographic binding methods for credential configuration. |
| mosip.certify.credential-config.credential-signing-alg-values-supported| Required          | Supported credential signing algorithm values. |
| mosip.certify.cache.redis.key-prefix                                   | Optional          | Prefix for Redis cache keys. |
| mosip.certify.credential-config.issuer.display                         | Required          | Issuer display configuration for credential configuration. |

### Additional Properties for DataProvider Plugin Mode

If `mosip.certify.plugin-mode` is set to `DataProvider`, the following new properties are applicable:

| Property Name                                                           | Required/Optional | Description |
|-------------------------------------------------------------------------|-------------------|-------------|
| mosip.certify.data-provider-plugin.credential-status.supported-purposes | Optional          | Supported purposes for credential status in DataProvider plugin. |
| mosip.certify.data-provider-plugin.did-url                              | Required          | DID URL for DataProvider plugin. |

### Modified Configuration Properties

The following properties have been modified in 0.12.0. Please update their values as per the new requirements. Sample values can be found in the [certify-default.properties](https://github.com/mosip/inji-config/blob/master/certify-default.properties) file. If missing, refer to other use-case specific certify properties files in the [inji-config repository](https://github.com/mosip/inji-config/tree/master).

| Property Name                        | Description |
|--------------------------------------|-------------|
| mosip.certify.cache.names            | List of cache names used in Inji Certify. |
| mosip.certify.cache.expire-in-seconds| Expiry time (in seconds) for cache entries. |

### Deprecated Configuration Properties

The following properties have been deprecated and moved to the database:

| Property Name                                         | Migration Required | Description |
|------------------------------------------------------|-------------------|-------------|
| mosip.certify.data-provider-plugin.issuer.vc-sign-algo | Yes - Database Migration | This property has been moved to the `credential_config` table as the `signature_crypto_suite` column. Use the PUT API of `/credential-configurations/{id}` endpoint to update this value for existing credential configurations. |

The following properties have been completely deprecated and can be removed from your configuration:

| Property Name                                         | Action Required | Description |
|------------------------------------------------------|----------------|-------------|
| mosip.certify.data-provider-plugin.issuer-public-key-uri | Remove from config | Property is no longer supported and should be removed. |
| mosip.certify.data-provider-plugin.issuer-uri       | Remove from config | Property is no longer supported and should be removed. |
| mosip.certify.supported.jwt-proof-alg               | Remove from config | Property is no longer supported and should be removed. |

> **Note:** For all new and modified properties, refer to the [certify-default.properties](https://github.com/mosip/inji-config/blob/master/certify-default.properties) file for sample values. If a property is missing, check other use-case specific certify properties files in the [inji-config repository](https://github.com/mosip/inji-config/tree/master).

---

## 3. Post-Upgrade Steps

Critical steps to perform in credential configuration after the upgrade:
- Update the `scope`, `key_manager_app_id`, `key_manager_ref_id` and `did_url` in the migrated credential configuration(credential_config) database table via direct DB update or using the credential-configuration API. Refer to [API documentation](https://mosip.stoplight.io/docs/inji-certify) for more details on request and API details.
- Restart all Inji Certify services after the upgrade.
- Verify application logs for errors or warnings.
- Test all critical workflows to ensure successful migration.

---

## 4. Troubleshooting

- Check the logs displayed in the console for details on the upgrade process and errors.
- Recheck the upgrade properties file for any misconfigurations.
- Ensure that the database user has sufficient privileges to perform schema changes.
- If the upgrade fails, review logs and resolve issues before retrying.