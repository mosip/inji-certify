# Deployment

## Pre-requisites
* Cluster creation and configuration [steps](https://docs.inji.io/readme/setup/deploy)
* inji-stack-config configmap [steps](https://docs.inji.io/readme/setup/deploy#pre-requisites)
* Postgres installation [steps](https://github.com/mosip/mosip-infra/tree/v1.2.0.2/deployment/v3/external/postgres)
* Config server secerts [steps](https://github.com/mosip/mosip-infra/tree/v1.2.0.2/deployment/v3/mosip/conf-secrets)
* Config server installation [steps](https://docs.inji.io/readme/setup/deploy#config-server-installation)
* Artifactory installation [steps](https://github.com/mosip/artifactory-ref-impl/tree/v1.3.0-beta.2/deploy)

* redis installation
```
cd deploy/redis
./install.sh
```

## Initialise pre-requisites
### [DB init](../db_scripts)
* Update values file for postgres init [here](../db_scripts/init_values.yaml).
  ```
   cd ../../db_scripts
  ./init_db.sh
  ```
## Install inji certify

  ```
   cd ../inji-certify
    ./install.sh
   ```
## [inji certify apitestrig](inji-certify-apitestrig)