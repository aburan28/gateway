.PHONY: generate generate-proto build test docker-build lint

generate: generate-proto
	@echo "TODO: run controller-gen for deepcopy generation and CRD manifests"

generate-proto:
	buf lint
	buf generate

build:
	go build ./...

test:
	go test ./...

docker-build:
	docker build -f Dockerfile.hub -t traffic-harvester/hub:dev .
	docker build -f Dockerfile.spoke -t traffic-harvester/spoke:dev .
	docker build -f Dockerfile.agent -t traffic-harvester/agent:dev .

lint:
	@echo "TODO: run golangci-lint once packages are implemented"