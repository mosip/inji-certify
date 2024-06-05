#!/bin/bash

set -e

download_and_extract() {
  local url=$1
  local dest_dir=$2
  shift 2
  local files_to_extract=("$@")
  local temp_zip=$(mktemp)

  wget -q "$url" -O "$temp_zip"

  for file in "${files_to_extract[@]}"; do
    unzip -o -j "$temp_zip" "$file" -d "$dest_dir"
  done

  rm -f "$temp_zip"
}

#if [ "$enable_esignet_artifactory" = "true" ]; then
#  download_and_extract "${artifactory_url_env}/artifactory/libs-release-local/esignet/esignet-wrapper.zip" "${loader_path_env}" "esignet-mock-wrapper.jar" "sunbird-rc-esignet-integration-impl.jar"
#fi

if [ "$enable_certify_artifactory" = "true" ]; then
  download_and_extract "${artifactory_url_env}/artifactory/libs-release-local/certify/certify-plugin.zip" "${loader_path_env}" "certify-sunbird-plugin.jar"
fi

echo "Installation complete"
cd $work_dir

exec "$@"