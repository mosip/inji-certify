#!/bin/bash
# Installs inji-certify
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

SOFTHSM_NS=softhsm
SOFTHSM_CHART_VERSION=1.3.0-beta.2

NS=inji-certify
CHART_VERSION=0.10.1-develop

echo Create $NS namespace
kubectl create ns $NS

echo Istio label
kubectl label ns $SOFTHSM_NS istio-injection=enabled --overwrite
helm repo add mosip https://mosip.github.io/mosip-helm
helm repo update

echo Installing Softhsm for certify
helm -n $SOFTHSM_NS install softhsm-certify mosip/softhsm -f softhsm-values.yaml --version $SOFTHSM_CHART_VERSION --wait
echo Installed Softhsm for certify

DEFAULT_INJICERTIFY_HOST=$( kubectl get cm inji-stack-config -n config-server -o jsonpath={.data.injicertify-host} )
# Check if INJICDERTIFY_HOST is present under configmap/inji-stack-config of configserver
if echo "DEFAULT_INJICERTIFY_HOST" | grep -q "CERTIFY_HOST"; then
    echo "CERTIFY_HOST is already present in configmap/inji-stack-config of configserver"
    MOSIP_INJICERTIFY_HOST=DEFAULT_INJICERTIFY_HOST
else
    read -p "Please provide injicertifyhost (eg: injicertify.sandbox.xyz.net ) : " INJICERTIFY_HOST

    if [ -z "INJICERTIFY_HOST" ]; then
    echo "INJICERTIFY Host not provided; EXITING;"
    exit 0;
    fi
fi

CHK_INJICERTIFY_HOST=$( nslookup "$INJICERTIFY_HOST" )
if [ $? -gt 0 ]; then
    echo "Injicertify Host does not exists; EXITING;"
    exit 0;
fi

echo "INJICERTIFY_HOST is not present in configmap/inji-stack-config of configserver"
    # Add injicertify host to inji-stack-config
    kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"injicertify-host\": \"$INJICERTIFY_HOST\"}}"
    kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"injicertify-host\": \"$INJICERTIFY_HOST\"}}"
    # Add the host
    kubectl -n config-server set env --keys=injicertify-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
    kubectl -n config-server set env --keys=security-pin --from secret/softhsm-certify deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_CERTIFY_
    # Restart the configserver deployment
    kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status

function installing_inji-certify() {

  echo Copy configmaps
  COPY_UTIL=../copy_cm_func.sh
  $COPY_UTIL configmap inji-stack-config default $NS
  $COPY_UTIL configmap artifactory-share artifactory $NS
  $COPY_UTIL configmap config-server-share config-server $NS
  $COPY_UTIL configmap softhsm-certify-share softhsm $NS

  echo Copy secrets
  ../copy_cm_func.sh secret softhsm-certify softhsm config-server


  INJICERTIFY_HOST=$(kubectl get cm inji-stack-config -o jsonpath={.data.injicertify-host})
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
  helm -n $NS install inji-certify mosip/inji-certify --set istio.hosts\[0\]=$INJICERTIFY_HOST --version $CHART_VERSION $ENABLE_INSECURE

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
