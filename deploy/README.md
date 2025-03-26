
# Deployment

## Install Pre-requisites
* Install pre-requisites
  ```
  ./install-prereq.sh
  ```
## Initialise pre-requisites
* Update values file for postgres init [here](postgres/init_values.yaml).
* Execute `initialise-prereq.sh` script to initialise postgres and copy secrets to config server.
  ```
  ./initialise-prereq.sh
  ```
## Install inji certify

  ```
   cd inji-certify
    ./install.sh
   ```
