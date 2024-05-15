#!/bin/bash

install_sunbird_rc() {
  cd ./docker-compose-sunbird
  echo "Installing Sunbird RC"
  bash setup_vault.sh docker-compose.yml vault
  docker compose up -d
  cd ..
}

install_esignet() {
  read -p "Please update the properties and press enter: " choice
  echo "Installing esignet"
  cd ./docker-compose-esignet
  docker compose up -d
  cd ..
}

display_menu() {
    echo "Select which services to install: "
    echo "1. Sunbird RC"
    echo "2. Esignet"
    echo "0. Exit"
}

# Function to handle user input
handle_input() {
    display_menu
    read -p "Select: " choice
    case $choice in
        1)
            install_sunbird_rc
            ;;
        2)
            install_esignet
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