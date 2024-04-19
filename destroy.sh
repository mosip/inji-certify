#!/bin/bash

cd docker-compose-esignet
  docker compose down
  sudo rm -rf data
cd ..

cd docker-compose-sunbird
	docker compose down
	sudo rm -rf data