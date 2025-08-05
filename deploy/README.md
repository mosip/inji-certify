# Deployment

## Pre-requisites
* Base infrastructure setup
  * Tool and utilities to be installed locally [steps](https://docs.inji.io/readme/setup/deploy#tools-and-utilities)
  * System Requirements: Hardware, network and certificate requirements [steps](https://docs.inji.io/readme/setup/deploy#system-requirements)
  * Set up Wireguard Bastion Host [steps](https://docs.inji.io/readme/setup/deploy#wireguard)
  * K8s Cluster setup [steps](https://docs.inji.io/readme/setup/deploy#k8-cluster-setup)
  * NGINX setup and configuration [steps](https://docs.inji.io/readme/setup/deploy#nginx-for-inji-k8-cluster)
  * K8s Cluster Configuration [steps](https://docs.inji.io/readme/setup/deploy#k8-cluster-configuration)
* inji-stack-config ConfigMap [steps](https://docs.inji.io/readme/setup/deploy#pre-requisites)
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