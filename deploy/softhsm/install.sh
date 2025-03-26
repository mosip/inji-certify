#!/bin/bash
# Installs Softhsm service for inji certify
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

SOFTHSM_NS=softhsm
SOFTHSM_CHART_VERSION=1.3.0-beta.2

function installing_softhsm() {
  echo Create $SOFTHSM_NS namespaces
  kubectl create ns $SOFTHSM_NS || true

  echo Istio label
  kubectl label ns $SOFTHSM_NS istio-injection=enabled --overwrite
  helm repo update

  # Deploy Softhsm for inji certify.
  echo "Installing Softhsm for inji cerity"
  helm -n "$SOFTHSM_NS" install softhsm-certify mosip/softhsm -f softhsm-values.yaml --version "$SOFTHSM_CHART_VERSION" --wait
  echo "Installed Softhsm for inji certify"

  return 0
}

# set commands for error handling.
set -e
set -o errexit   ## set -e : exit the script if any statement returns a non-true return value
set -o nounset   ## set -u : exit the script if you try to use an uninitialised variable
set -o errtrace  # trace ERR through 'time command' and other functions
set -o pipefail  # trace ERR through pipes
installing_softhsm   # calling function
