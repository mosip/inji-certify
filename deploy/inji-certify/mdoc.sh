#!/bin/bash

generate_keys() {
    local filename_prefix=$1
    local password=$2

    PRIVATE_KEY_FILE="${filename_prefix}_private_key.pem"
    PRIVATE_KEY_FILE_IN_DER_FORMAT="${filename_prefix}_private.der"
    CERTIFICATE_FILE="${filename_prefix}_certificate.pem"

    openssl ecparam -name prime256v1 -genkey -noout -out $PRIVATE_KEY_FILE
    # Generate an EC k1 private key
    # openssl ecparam -name secp256k1 -genkey -noout -out $PRIVATE_KEY_FILE
    #
    # Generate an Ed25519 private key
    # openssl genpkey -algorithm ED25519 -out $PRIVATE_KEY_FILE
    openssl pkcs8 -topk8 -inform PEM -outform DER -in "${PRIVATE_KEY_FILE}" -nocrypt -out "${PRIVATE_KEY_FILE_IN_DER_FORMAT}"
    echo "Encoding the private key to Base64..."
    base64EncodedPrivateKey=$(base64 -i $PRIVATE_KEY_FILE_IN_DER_FORMAT)

    echo "Creating certificate..."
    openssl req -new -key $PRIVATE_KEY_FILE -out cert_request.csr
    openssl x509 -req -days 365 -in cert_request.csr -signkey $PRIVATE_KEY_FILE -out $CERTIFICATE_FILE -passin pass:$password -extensions v3_req
    echo "Encoding the certificate to Base64..."
    base64EncodedCertificate=$(base64 -i $CERTIFICATE_FILE)

    echo "Secret created successfully..."
    echo "Adding the contents into a file"
    echo "Note: Make sure to add the generated secret without any newlines in the value, as new lines presence would cause issues when service loads the secret"
    echo -n "$base64EncodedPrivateKey||$base64EncodedCertificate" > issuerSecret.txt

    echo "------------------------------------------------------------------------------"
    echo "secret is now available in issuerSecret.txt"
    echo "------------------------------------------------------------------------------"

    echo "removing the files created"
    rm $PRIVATE_KEY_FILE
    rm $PRIVATE_KEY_FILE_IN_DER_FORMAT
    rm $CERTIFICATE_FILE
    rm cert_request.csr

}

#Inputs that needs to be added
# Country Name (2 letter code) [AU]:
# State or Province Name (full name) [Some-State]:
# Locality Name (eg, city) []:
# Organization Name (eg, company) [Internet Widgits Pty Ltd]:
# Organizational Unit Name (eg, section) []:
# Common Name (e.g. server FQDN or YOUR name) []:
# Email Address []:
echo "Secret creation process started"
generate_keys "mock_issuer" "password"