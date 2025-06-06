#!/bin/bash
# Installs inji-certify
## Usage: ./install.sh [kubeconfig]

if [ $# -ge 1 ]; then
  export KUBECONFIG=$1
fi

SOFTHSM_NS=softhsm
SOFTHSM_CHART_VERSION=1.3.0-beta.2

echo "Create $SOFTHSM_NS namespace"
kubectl create ns $SOFTHSM_NS

NS=inji-certify
CHART_VERSION=0.0.1-develop

echo "Create $NS namespace"
kubectl create ns $NS

echo "Labeling namespace with Istio injection"
kubectl label ns $SOFTHSM_NS istio-injection=enabled --overwrite
helm repo add mosip https://mosip.github.io/mosip-helm
helm repo update

echo "Installing Softhsm for certify"
helm -n $SOFTHSM_NS install softhsm-certify mosip/softhsm -f softhsm-values.yaml --version $SOFTHSM_CHART_VERSION --wait
echo "Installed Softhsm for certify"

function installing_inji-certify() {
  echo "Copy configmaps"
  COPY_UTIL=../copy_cm_func.sh
  $COPY_UTIL configmap artifactory-share artifactory $NS
  $COPY_UTIL configmap config-server-share config-server $NS
  $COPY_UTIL configmap softhsm-certify-share softhsm $NS

  echo "Copy secrets"
  ../copy_cm_func.sh secret softhsm-certify softhsm config-server

  # Prompt until valid usecase is chosen
  while true; do
    echo "Please choose the required usecase to proceed with installation:"
    echo "1) mock-identity"
    echo "2) mosipid-identity"
    echo "3) sunbird-insurance"
    echo "4) landregistry"
    echo "5) mock-mdl"
    read -p "Enter option [1-5]: " usecase_option

    case $usecase_option in
      1)
        PROFILE_VALUE="default,mock-identity"

        echo "Please provide the hostname for the injicertify mock:"
        read -p "injicertify mock host (e.g., injicertify-mock.sandbox.xyz.net): " INJICERTIFY_HOST

        echo "Please provide the hostname for the mockidentitysystem:"
        read -p "mockidentitysystem host (e.g., api.sandbox.xyz.net): " MOCK_IDENTITY_HOST

        echo "Please provide the hostname for the esignet mock:"
        read -p "esignet mock host (e.g., esignet-mock.sandbox.xyz.net): " ESIGNET_MOCK_HOST

        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"injicertify-mock-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"injicertify-mock-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"mockidentitysystem-host\": \"$MOCK_IDENTITY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"mockidentitysystem-host\": \"$MOCK_IDENTITY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"esignet-mock-host\": \"$ESIGNET_MOCK_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"esignet-mock-host\": \"$ESIGNET_MOCK_HOST\"}}"

        kubectl -n config-server set env --keys=injicertify-mock-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_
        kubectl -n config-server set env --keys=mockidentitysystem-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_API_
        kubectl -n config-server set env --keys=esignet-mock-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_

        kubectl -n config-server set env --keys=security-pin --from secret/softhsm-certify deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_CERTIFY_
        kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status
        break
        ;;
      2)
        PROFILE_VALUE="default,mosipid-identity"

        echo "Please provide the hostname for the injicertify mosipid:"
        read -p "injicertify mosipid host (e.g., injicertify-mosipid.sandbox.xyz.net): " INJICERTIFY_HOST

        echo "Please provide the hostname for the esignet mosipid identity:"
        read -p "esignet mosipid identity host (e.g., esignet-mosipid.sandbox.xyz.net): " ESIGNET_MOSIPID_HOST
        read -p "Please provide the hostname for the ida and authmanager (e.g., api-internal.sandbox.xyz.net): " IDA_EXTERNAL_HOST

        read -p "Please provide mosip ida client secret: " IDA_CLIENT_SECRET
        read -p "Please provide certify misp licence key: " CERTIFY_MISP_KEY
        read -p "Please provide the hostname for the redis server ( default: redis-master-0.redis-headless.redis.svc.cluster.local ): " REDIS_HOST
        REDIS_HOST_DEFAULT="redis-master-0.redis-headless.redis.svc.cluster.local"
        read -p "Please provide the hostname for the redis server (default: $REDIS_HOST_DEFAULT): " REDIS_HOST
        REDIS_HOST=${REDIS_HOST:-$REDIS_HOST_DEFAULT}
        REDIS_PORT_DEFAULT="6379"
        read -p "Please provide the port for the redis server (default: $REDIS_PORT_DEFAULT): " REDIS_PORT
        REDIS_PORT=${REDIS_PORT:-$REDIS_PORT_DEFAULT}

        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"injicertify-mosipid-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"injicertify-mosipid-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"mosipid-identity-esignet-host\": \"$ESIGNET_MOSIPID_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"mosipid-identity-esignet-host\": \"$ESIGNET_MOSIPID_HOST\"}}"
        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"mosip-api-cre-internal-host\": \"$IDA_EXTERNAL_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"mosip-api-cre-internal-host\": \"$IDA_EXTERNAL_HOST\"}}"
        kubectl create configmap redis-config --from-literal=redis-host="$REDIS_HOST" -n config-server --dry-run=client -o yaml | kubectl apply -f -
        kubectl create configmap redis-config --from-literal=redis-port="$REDIS_PORT" -n config-server --dry-run=client -o yaml | kubectl apply -f -
        kubectl create secret generic certify-misp-onboarder-key --from-literal=certify-misp-key="$CERTIFY_MISP_KEY" -n config-server --dry-run=client -o yaml | kubectl apply -f -
        kubectl create secret generic keycloak-client-secrets --from-literal=mosip_ida_client_secret="$IDA_CLIENT_SECRET" -n config-server --dry-run=client -o yaml | kubectl apply -f -
        kubectl create secret generic redis --from-literal=redis-password="$REDIS_PASSWORD" -n config-server --dry-run=client -o yaml | kubectl apply -f -

        kubectl -n config-server set env --keys=injicertify-mosipid-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_
        kubectl -n config-server set env --keys=mosipid-identity-esignet-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
        kubectl -n config-server set env --keys=mosip-api-cre-internal-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
        kubectl -n config-server set env --keys=redis-host --from configmap/redis-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
        kubectl -n config-server set env --keys=redis-port --from configmap/redis-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_

        kubectl -n config-server set env --keys=certify-misp-key --from secret/certify-misp-onboarder-key deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_
        kubectl -n config-server set env --keys=mosip_ida_client_secret --from secret/keycloak-client-secrets deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
        kubectl -n config-server set env --keys=redis-password --from secret/redis deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_

        kubectl -n config-server set env --keys=security-pin --from secret/softhsm-certify deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_CERTIFY_
        kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status
        echo "Copy configmaps"
        ../copy_cm_func.sh configmap redis-config config-server $NS
        ../copy_cm_func.sh secret redis config-server $NS
        ../copy_cm_func.sh secret keycloak-client-secrets config-server $NS
        ../copy_cm_func.sh secret certify-misp-onboarder-key config-server $NS

        break
        ;;
      3)
        PROFILE_VALUE="default,sunbird-insurance"

        echo "Please provide the hostname for the injicertify insurance:"
        read -p "injicertify insurance host (e.g., injicertify-insurance.sandbox.xyz.net): " INJICERTIFY_HOST

        echo "Please provide the URL for the sunbird registry:"
        read -p "sunbird registry url (e.g., https://registry.sandbox.xyz.net): " SUNBIRD_REGISTRY_URL

        echo "Please provide the hostname for the esignet insurance:"
        read -p "esignet insurance host (e.g., esignet-insurance.sandbox.xyz.net): " ESIGNET_INSURANCE_HOST

        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"injicertify-insurance-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"injicertify-insurance-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"sunbird-url\": \"$SUNBIRD_REGISTRY_URL\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"sunbird-url\": \"$SUNBIRD_REGISTRY_URL\"}}"
        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"esignet-insurance-host\": \"$ESIGNET_INSURANCE_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"esignet-insurance-host\": \"$ESIGNET_INSURANCE_HOST\"}}"

        kubectl -n config-server set env --keys=injicertify-insurance-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_
        kubectl -n config-server set env --keys=sunbird-url --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_
        kubectl -n config-server set env --keys=esignet-insurance-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_

        kubectl -n config-server set env --keys=security-pin --from secret/softhsm-certify deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_CERTIFY_
        kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status

        break
        ;;
      4)
        PROFILE_VALUE="default,postgres-landregistry"

        echo "Please provide the hostname for the injicertify landregistry:"
        read -p "injicertify landregistry host (e.g., injicertify-landregistry.sandbox.xyz.net): " INJICERTIFY_HOST

        echo "Please provide the hostname for the esignet mock:"
        read -p "esignet mock host (e.g., esignet-mock.sandbox.xyz.net): " ESIGNET_MOCK_HOST

        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"injicertify-landregistry-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"injicertify-landregistry-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"esignet-mock-host\": \"$ESIGNET_MOCK_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"esignet-mock-host\": \"$ESIGNET_MOCK_HOST\"}}"

        kubectl -n config-server set env --keys=injicertify-landregistry-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_
        kubectl -n config-server set env --keys=esignet-mock-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_

        kubectl -n config-server set env --keys=security-pin --from secret/softhsm-certify deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_CERTIFY_
        kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status

        break
        ;;
      5)
        PROFILE_VALUE="default,mock-mdl"

        echo "Please provide the hostname for the injicertify mdl:"
        read -p "injicertify mdl host (e.g., injicertify-mdl.sandbox.xyz.net): " INJICERTIFY_HOST

        echo "Please provide the hostname for the esignet mock:"
        read -p "esignet mock host (e.g., esignet-mock.sandbox.xyz.net): " ESIGNET_MOCK_HOST

        echo "Running mdoc.sh to generate issuer keycert"
        chmod +x mdoc.sh
        ./mdoc.sh

        if [[ ! -f issuerSecret.txt ]]; then
          echo "issuerSecret.txt not found after running mdoc.sh"
          exit 1
        fi

        echo "Creating  secret 'mdoc issuer keycert' "
        kubectl create secret generic mosip-certify-mock-mdoc-issuer-keycert --from-file=mosip-certify-mock-mdoc-issuer-keycert=issuerSecret.txt -n config-server --dry-run=client -o yaml | kubectl apply -f -
        rm issuerSecret.txt

        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"injicertify-mdl-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"injicertify-mdl-host\": \"$INJICERTIFY_HOST\"}}"
        kubectl patch configmap inji-stack-config -n config-server --type merge -p "{\"data\": {\"esignet-mock-host\": \"$ESIGNET_MOCK_HOST\"}}"
        kubectl patch configmap inji-stack-config -n default --type merge -p "{\"data\": {\"esignet-mock-host\": \"$ESIGNET_MOCK_HOST\"}}"

        kubectl -n config-server set env --keys=injicertify-mdl-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_
        kubectl -n config-server set env --keys=esignet-mock-host --from configmap/inji-stack-config deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_MOSIP_

        kubectl -n config-server set env --keys=mosip-certify-mock-mdoc-issuer-keycert --from secret/mosip-certify-mock-mdoc-issuer-keycert deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_
        kubectl -n config-server set env --keys=security-pin --from secret/softhsm-certify deployment/config-server --prefix=SPRING_CLOUD_CONFIG_SERVER_OVERRIDES_SOFTHSM_CERTIFY_
        kubectl -n config-server get deploy -o name | xargs -n1 -t kubectl -n config-server rollout status
        echo "Copy secrets"
        ../copy_cm_func.sh secret mosip-certify-mock-mdoc-issuer-keycert config-server $NS
        break
        ;;
      *)
        echo "Invalid option selected. Please enter a number between 1 and 5."
        ;;
    esac
  done

  echo "Copy configmaps"
  ../copy_cm_func.sh configmap inji-stack-config default $NS

  echo "Patching configmap 'config-server-share' with active_profile_env = $PROFILE_VALUE"
  kubectl -n $NS patch configmap config-server-share --type merge -p "{\"data\": {\"active_profile_env\": \"$PROFILE_VALUE\"}}"

  echo "Do you have public domain & valid SSL? (Y/n) "
  echo "Y: if you have public domain & valid ssl certificate"
  echo "n: If you don't have a public domain and a valid SSL certificate. Note: It is recommended to use this option only in development environments."
  read -p "" flag

  if [ -z "$flag" ]; then
    echo "No input provided; exiting."
    exit 1
  fi

  ENABLE_INSECURE=""
  if [ "$flag" = "n" ]; then
    ENABLE_INSECURE="--set enable_insecure=true"
  fi

  echo "Installing inji-certify service..."
  helm -n $NS install inji-certify mosip/inji-certify \
    --set istio.hosts[0]=$INJICERTIFY_HOST \
    --version $CHART_VERSION $ENABLE_INSECURE

  kubectl -n $NS get deploy -o name | xargs -n1 -t kubectl -n $NS rollout status
  echo "Installed inji-certify service"
  return 0
}

# set commands for error handling
set -e
set -o errexit
set -o nounset
set -o errtrace
set -o pipefail

installing_inji-certify
