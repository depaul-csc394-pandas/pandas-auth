LOCAL := registry.me:5000
TAG := $$(git log -1 --pretty=%h)
AUTH_NAME := pandas/auth
AUTH_IMG := ${AUTH_NAME}:${TAG}
AUTH_LATEST := ${AUTH_NAME}:latest
DB_NAME := pandas/auth-db
DB_IMG := ${DB_NAME}:${TAG}
DB_LATEST := ${DB_NAME}:latest

build:
	@docker build -t ${AUTH_IMG} -f Dockerfile.auth .
	@docker build -t ${DB_IMG} -f Dockerfile.db .
	@docker tag ${AUTH_IMG} ${AUTH_LATEST}
	@docker tag ${DB_IMG} ${DB_LATEST}

push-local:
	@docker tag ${AUTH_IMG} ${LOCAL}/${AUTH_NAME}
	@docker tag ${DB_IMG} ${LOCAL}/${DB_NAME}
	@docker push ${LOCAL}/${AUTH_NAME}
	@docker push ${LOCAL}/${DB_NAME}

stack-deploy:
	@docker stack deploy pandas-auth --compose-file=docker-compose.yml

stack-rm:
	@docker stack rm pandas-auth
