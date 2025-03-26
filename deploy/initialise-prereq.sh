#!/bin/bash

# Initializes prerequisite services for Esignet
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

ROOT_DIR=`pwd`

function prompt_for_initialisation() {
  local module_name=$1
  local prompt_message=$2
  read -p "$prompt_message (y/n): " response
  # Check for valid input
  if [[ "$response" != "y" && "$response" != "Y" && "$response" != "n" && "$response" != "N" ]]; then
    echo "Incorrect input. Please enter 'y' or 'n'."
    exit 1
  fi
  if [[ "$response" == "y" || "$response" == "Y" ]]; then
    cd $ROOT_DIR/"$module_name"
    ./$module_name-init.sh
  else
    echo "Skipping initialization of $module_name."
  fi
}

function initialising_prerequisites() {
  declare -a modules=("postgres")
  declare -A prompts=(
    ["postgres"]="Do you want to continue executing postgres init?"
  )

  echo "Initializing prerequisite services"

  for module in "${modules[@]}"
  do
      prompt_for_initialisation "$module" "${prompts[$module]}"
  done

  echo "Copying db-common-secrets to config-server namespace"
  ../copy_cm_func.sh secret db-common-secrets postgres config-server

  echo "Copying softhsm-certify to config-server namespace"
  ../copy_cm_func.sh secret softhsm-certify softhsm config-server

  echo "Copying redis secret to config-server namespace"
  ../copy_cm_func.sh secret redis redis config-server

  echo "Updating environment variables in config-server"
  kubectl -n config-server set env --keys=db-common-secrets --from secret/db-common-secrets deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
  kubectl -n config-server set env --keys=security-pin --from secret/softhsm-certify deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_CERTIFY_
  kubectl -n config-server set env --keys=redis-password --from secret/redis deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_

  echo "Waiting for config-server rollout to complete"
  kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status

  echo "All prerequisite services initialized successfully."
  return 0
}

# Set commands for error handling.
set -e
set -o errexit   ## set -e : exit the script if any statement returns a non-true return value
set -o nounset   ## set -u : exit the script if you try to use an uninitialized variable
set -o errtrace  # trace ERR through 'time command' and other functions
set -o pipefail  # trace ERR through pipes
initialising_prerequisites   # calling function
