package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"io/ioutil"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	spc "github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

// This is mostly a copy of
// https://github.com/spiffe/spire/blob/62e723fafafe322cb68e4d494d96cb29695a7b37/pkg/server/plugin/nodeattestor/k8s/psat/psat.go

const (
	pluginName       = "pod_sidecar"
	defaultTokenPath = "/var/run/secrets/tokens/spire-agent"
)

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *AttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p))
}

// New creates a new PSAT attestor plugin
func New() *AttestorPlugin {
	return &AttestorPlugin{}
}

// AttestorPlugin is a PSAT (projected SAT) attestor plugin
type AttestorPlugin struct {
	mu     sync.RWMutex
	config *attestorConfig
}

// AttestorConfig holds configuration for AttestorPlugin
type AttestorConfig struct {
	// Cluster name where the agent lives
	Cluster string `hcl:"cluster"`
	// File path of PSAT
	TokenPath string `hcl:"token_path"`
}

type attestorConfig struct {
	trustDomain string
	cluster     string
	tokenPath   string
}

// FetchAttestationData loads PSAT from the configured path and send it to server node attestor
func (p *AttestorPlugin) FetchAttestationData(stream nodeattestor.NodeAttestor_FetchAttestationDataServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	token, err := loadTokenFromFile(config.tokenPath)
	if err != nil {
		return fmt.Errorf("unable to load token from %s: %v", config.tokenPath, err)
	}

	data, err := json.Marshal(k8s.PSATAttestationData{
		Cluster: config.cluster,
		Token:   token,
	})
	if err != nil {
		return err
	}

	return stream.Send(&nodeattestor.FetchAttestationDataResponse{
		AttestationData: &spc.AttestationData{
			Type: pluginName,
			Data: data,
		},
	})
}

// Configure decodes JSON config from request and populates AttestorPlugin with it
func (p *AttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (resp *spi.ConfigureResponse, err error) {
	hclConfig := new(AttestorConfig)
	if err := hcl.Decode(hclConfig, req.Configuration); err != nil {
		return nil, fmt.Errorf("unable to decode configuration: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("global configuration missing trust domain")
	}
	if hclConfig.Cluster == "" {
		return nil, errors.New("configuration missing cluster")
	}

	config := &attestorConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		cluster:     hclConfig.Cluster,
		tokenPath:   hclConfig.TokenPath,
	}
	if config.tokenPath == "" {
		config.tokenPath = defaultTokenPath
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *AttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *AttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, errors.New("not configured")
	}
	return p.config, nil
}

func (p *AttestorPlugin) setConfig(config *attestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func loadTokenFromFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("%q is empty", path)
	}
	return string(data), nil
}

func main() {
	catalog.PluginMain(BuiltIn())
}
