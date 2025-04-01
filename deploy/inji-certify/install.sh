#!/bin/bash
# Installs inji-certify
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ] ; then
  export KUBECONFIG=$1
fi

NS=inji-certify
CHART_VERSION=0.10.1-develop

echo Create $NS namespace
kubectl create ns $NS

DEFAULT_MOSIP_INJICERTIFY_HOST=$( kubectl get cm global -n config-server -o jsonpath={.data.mosip-injicertify-host} )
# Check if MOSIP_INJICDERTIFY_HOST is present under configmap/global of configserver
if echo "DEFAULT_MOSIP_INJICERTIFY_HOST" | grep -q "MOSIP_CERTIFY_HOST"; then
    echo "MOSIP_CERTIFY_HOST is already present in configmap/global of configserver"
    MOSIP_INJICERTIFY_HOST=DEFAULT_MOSIP_INJICERTIFY_HOST
else
    read -p "Please provide injicertifyhost (eg: injicertify.sandbox.xyz.net ) : " MOSIP_INJICERTIFY_HOST

    if [ -z "MOSIP_INJICERTIFY_HOST" ]; then
    echo "INJICERTIFY Host not provided; EXITING;"
    exit 0;
    fi
fi

CHK_MOSIP_INJICERTIFY_HOST=$( nslookup "$MOSIP_INJICERTIFY_HOST" )
if [ $? -gt 0 ]; then
    echo "Injicertify Host does not exists; EXITING;"
    exit 0;
fi

echo "MOSIP_INJICERTIFY_HOST is not present in configmap/global of configserver"
    # Add injicertify host to global
    kubectl patch configmap global -n config-server --type merge -p "{\"data\": {\"mosip-injicertify-host\": \"$MOSIP_INJICERTIFY_HOST\"}}"
    kubectl patch configmap global -n default --type merge -p "{\"data\": {\"mosip-injicertify-host\": \"$MOSIP_INJICERTIFY_HOST\"}}"
    # Add the host
    kubectl -n config-server set env --keys=mosip-injicertify-host --from configmap/global deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
    # Restart the configserver deployment
    kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status

function installing_inji-certify() {

  helm repo add mosip https://mosip.github.io/mosip-helm
  helm repo update

  echo Copy configmaps
  COPY_UTIL=../copy_cm_func.sh
  $COPY_UTIL configmap global default $NS
  $COPY_UTIL configmap artifactory-share artifactory $NS
  $COPY_UTIL configmap config-server-share config-server $NS
  $COPY_UTIL configmap softhsm-certify-share softhsm $NS


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
