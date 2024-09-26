#!/bin/bash

install_sunbird_rc() {
  cd ./docker-compose-sunbird
  echo "Installing Sunbird RC"
  bash setup_vault.sh docker-compose.yml vault
  docker compose up -d
  cd ..
}

install_certify() {
  read -p "Please update the properties and press enter: " choice
  echo "Installing certify"
  cd ./docker-compose-certify
  docker compose up -d
  cd ..
}

display_menu() {
    echo "Select which services to install: "
    echo "1. Sunbird RC"
    echo "2. Certify"
    echo "0. Exit"
}

# Function to handle user input
handle_input() {
    docker network inspect mosip_network >/dev/null 2>&1 || \
        docker network create --driver bridge mosip_network

    display_menu
    read -p "Select: " choice
    case $choice in
        1)
            install_sunbird_rc
            ;;
        2)
            install_certify
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid choice. Please enter a number between 0 and 3."
            handle_input
            ;;
    esac
}

# Main function
main() {
    while true; do
        handle_input
    done
}

# Start the script
main