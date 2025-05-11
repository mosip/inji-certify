if [[ "$1" == "--force-reset" ]]; then
  echo "Resetting PostgreSQL Database..."
  docker volume rm sunbirdrc_db_data  # Adjust volume name as needed
  docker-compose down
  docker-compose up -d
fi
