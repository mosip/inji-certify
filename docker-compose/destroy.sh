#!/bin/bash

cd docker-compose-certify
  docker compose down
  sudo rm -rf data
cd ..

cd docker-compose-sunbird
	docker compose down
	sudo rm -rf data

docker network rm mosip_network
