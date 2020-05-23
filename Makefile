out_dir := out/bin

export GO111MODULE=on
export GOPROXY=https://proxy.golang.org

build: clean
	cd cmd/server && GOOS=linux GOARCH=amd64 go build -o ../../../$(out_dir)/server/k8s-sidecar-attestor  -i
	cd cmd/agent  && GOOS=linux GOARCH=amd64 go build -o ../../../$(out_dir)/server/k8s-sidecar-attestor  -i

test:
	go test -race ./cmd/... ./pkg/...

clean:
	go clean ./cmd/... ./pkg/...
	rm -rf out
