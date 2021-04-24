NAME := mcdobr/yawaf
TAG := $$(git rev-parse HEAD)
IMG := ${NAME}:${TAG}
LATEST := ${NAME}:latest

docker-build:
	@docker build -t ${IMG} .
	@docker tag ${IMG} ${LATEST}

docker-build-no-cache:
	@docker build --no-cache -t ${IMG} .
	@docker tag ${IMG} ${LATEST}

docker-debug:
	@docker run -it --entrypoint /bin/sh mcdobr/yawaf:latest
