#!/bin/bash
# Installs inji-certify
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

SOFTHSM_NS=softhsm
SOFTHSM_CHART_VERSION=0.0.1-develop

echo Create $SOFTHSM_NS namespace
kubectl create ns $SOFTHSM_NS

NS=inji-certify
CHART_VERSION=0.0.1-develop

echo Create $NS namespace
kubectl create ns $NS

function installing_inji-certify() {

  echo Istio label
  kubectl label ns $SOFTHSM_NS istio-injection=enabled --overwrite
  helm repo add mosip https://mosip.github.io/mosip-helm
  helm repo update

  echo Installing Softhsm for certify
  helm -n $SOFTHSM_NS install softhsm-certify mosip/softhsm -f softhsm-values.yaml --version $SOFTHSM_CHART_VERSION --wait
  echo Installed Softhsm for certify

  echo Copy configmaps
  ./copy_cm_func.sh configmap global default config-server

  echo Copy secrets
  ./copy_cm_func.sh secret softhsm-certify softhsm config-server

  kubectl -n config-server set env --keys=mosip-injicertify-host --from configmap/global deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
  kubectl -n config-server set env --keys=security-pin --from secret/softhsm-certify deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_CERTIFY_
  kubectl -n config-server get deploy -o name |  xargs -n1 -t  kubectl -n config-server rollout status

  echo Copy configmaps
  sed -i 's/\r$//' copy_cm.sh
  ./copy_cm.sh

  INJICERTIFY_HOST=$(kubectl get cm global -o jsonpath={.data.mosip-injicertify-host})
  echo "Do you have public domain & valid SSL? (Y/n) "
  echo "Y: if you have public domain & valid ssl certificate"
  echo "n: If you don't have a public domain and a valid SSL certificate. Note: It is recommended to use this option only in development environments."
  read -p "" flag

  if [ -z "$flag" ]; then
    echo "'flag' was provided; EXITING;"
    exit 1;
  fi
  ENABLE_INSECURE=''
  if [ "$flag" = "n" ]; then
    ENABLE_INSECURE='--set enable_insecure=true';
  fi

  echo Running inji-certify
  helm -n $NS install inji-certify mosip/inji-certify --set image.repository=mosipqa/inji-certify --set image.tag=0.9.x --set istio.hosts\[0\]=$INJICERTIFY_HOST --version $CHART_VERSION $ENABLE_INSECURE

  kubectl -n $NS  get deploy -o name |  xargs -n1 -t  kubectl -n $NS rollout status

  echo Installed inji-certify service
  return 0
}

# set commands for error handling.
set -e
set -o errexit   ## set -e : exit the script if any statement returns a non-true return value
set -o nounset   ## set -u : exit the script if you try to use an uninitialised variable
set -o errtrace  # trace ERR through 'time command' and other functions
set -o pipefail  # trace ERR through pipes
installing_inji-certify  # calling function
