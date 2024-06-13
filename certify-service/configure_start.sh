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

#installs the pkcs11 libraries.
set -e

DEFAULT_ZIP_PATH=artifactory/libs-release-local/hsm/client.zip
[ -z "$hsm_zip_file_path" ] && zip_path="$DEFAULT_ZIP_PATH" || zip_path="$hsm_zip_file_path"

echo "Download the client from $artifactory_url_env"
echo "Zip File Path: $zip_path"

wget -q "$artifactory_url_env/$zip_path"
echo "Downloaded $artifactory_url_env/$zip_path"

FILE_NAME=${zip_path##*/}

DIR_NAME=$hsm_local_dir_name

has_parent=$(zipinfo -1 "$FILE_NAME" | awk '{split($NF,a,"/");print a[1]}' | sort -u | wc -l)
if test "$has_parent" -eq 1; then
  echo "Zip has a parent directory inside"
  dirname=$(zipinfo -1 "$FILE_NAME" | awk '{split($NF,a,"/");print a[1]}' | sort -u | head -n 1)
  echo "Unzip directory"
  unzip $FILE_NAME
  echo "Renaming directory"
  mv -v $dirname $DIR_NAME
else
  echo "Zip has no parent directory inside"
  echo "Creating destination directory"
  mkdir "$DIR_NAME"
  echo "Unzip to destination directory"
  unzip -d "$DIR_NAME" $FILE_NAME
fi

echo "Attempting to install"
cd ./$DIR_NAME && chmod +x install.sh && sudo ./install.sh


cd $work_dir

exec "$@"