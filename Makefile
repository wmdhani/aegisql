.PHONY: up down restart build logs shell-db shell-api

# Menjalankan seluruh sistem di background
up:
	docker compose up -d

# Mematikan sistem dan menghapus volume (reset data)
down:
	docker compose down -v

# Membangun ulang image Docker
build:
	docker compose build

# Melihat log aplikasi secara realtime
logs:
	docker compose logs -f

# Masuk ke terminal MySQL container
shell-db:
	docker compose exec target-db mysql -u root -p

# Masuk ke terminal Backend container
shell-api:
	docker compose exec bastion-api bash