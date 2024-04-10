.PHONY: start

start:
	bash setup_vault.sh docker-compose.yml vault
	docker compose up -d

destroy:
	docker compose down
	sudo rm -rf data db-data
	docker volume rm demo-mosip-rc_vault-data
