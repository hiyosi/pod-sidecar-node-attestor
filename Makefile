out_dir := out/bin

SPIRE_VERSION=0.10.0

GOROOT ?= /usr/local/go
GO111MODULE=on
GOPROXY=https://proxy.golang.org

build: clean
	cd cmd/server && GOOS=linux GOARCH=amd64 $(GOROOT)/bin/go build -o ../../$(out_dir)/server/pod-sidecar-node-attestor  -i
	cd cmd/agent  && GOOS=linux GOARCH=amd64 $(GOROOT)/bin/go build -o ../../$(out_dir)/agent/pod-sidecar-node-attestor  -i

build-docker-image:
	docker build -f ./build/docker/Dockerfile.server --build-arg SPIRE_VERSION=${SPIRE_VERSION} -t hiyosi/spire-server:${SPIRE_VERSION} .
	docker build -f ./build/docker/Dockerfile.agent --build-arg SPIRE_VERSION=${SPIRE_VERSION} -t hiyosi/spire-agent:${SPIRE_VERSION} .

test:
	${GOROOT}/bin/go test -race ./cmd/... ./pkg/...

clean:
	${GOROOT}/bin/go clean ./cmd/... ./pkg/...
	rm -rf out
