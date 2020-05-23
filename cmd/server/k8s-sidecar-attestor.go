package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/plugin/k8s"
	"github.com/spiffe/spire/pkg/common/plugin/k8s/apiserver"
	"github.com/spiffe/spire/pkg/server/plugin/nodeattestor"
	spc "github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
)

// This is mostly a copy of
// https://github.com/spiffe/spire/blob/62e723fafafe322cb68e4d494d96cb29695a7b37/pkg/server/plugin/nodeattestor/k8s/psat/psat.go

const (
	pluginName = "k8s_sidecar"
)

var (
	defaultAudience = []string{"spire-server"}
)

type K8sSidecarAttestorPlugin struct {
	logger hclog.Logger
	mu     sync.RWMutex
	config *attestorConfig
}

type K8sSidecarAttestorPluginConfig struct {
	Clusters map[string]*ClusterConfig `hcl:"clusters"`
}

// ClusterConfig holds a single cluster configuration
type ClusterConfig struct {
	// Array of whitelisted service accounts names
	// Attestation is denied if coming from a service account that is not in the list
	ServiceAccountWhitelist []string `hcl:"service_account_whitelist"`

	// Audience for PSAT token validation
	// If audience is not configured, defaultAudience will be used
	// If audience value is set to an empty slice, k8s apiserver audience will be used
	Audience *[]string `hcl:"audience"`

	// Kubernetes configuration file path
	// Used to create a k8s client to query the API server. If string is empty, in-cluster configuration is used
	KubeConfigFile string `hcl:"kube_config_file"`

	// Node labels that are allowed to use as selectors
	AllowedNodeLabelKeys []string `hcl:"allowed_node_label_keys"`

	// Pod labels that are allowed to use as selectors
	AllowedPodLabelKeys []string `hcl:"allowed_pod_label_keys"`
}

type attestorConfig struct {
	trustDomain string
	clusters    map[string]*clusterConfig
}

type clusterConfig struct {
	serviceAccounts      map[string]bool
	audience             []string
	client               apiserver.Client
	allowedNodeLabelKeys map[string]bool
	allowedPodLabelKeys  map[string]bool
}

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *K8sSidecarAttestorPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, nodeattestor.PluginServer(p))
}

// New creates a new attestor plugin
func New() *K8sSidecarAttestorPlugin {
	return &K8sSidecarAttestorPlugin{}
}

func (p *K8sSidecarAttestorPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	if req.AttestationData == nil {
		return errors.New("missing attestation data")
	}

	if dataType := req.AttestationData.Type; dataType != pluginName {
		return fmt.Errorf("unexpected attestation data type %q", dataType)
	}

	if req.AttestationData.Data == nil {
		return errors.New("missing attestation data payload")
	}

	attestationData := new(k8s.PSATAttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return fmt.Errorf("failed to unmarshal data payload: %v", err)
	}

	if attestationData.Cluster == "" {
		return errors.New("missing cluster in attestation data")
	}

	if attestationData.Token == "" {
		return errors.New("missing token in attestation data")
	}

	cluster := config.clusters[attestationData.Cluster]
	if cluster == nil {
		return fmt.Errorf("not configured for cluster %q", attestationData.Cluster)
	}

	tokenStatus, err := cluster.client.ValidateToken(attestationData.Token, cluster.audience)
	if err != nil {
		return fmt.Errorf("unable to validate token with TokenReview API: %v", err)
	}

	if !tokenStatus.Authenticated {
		return errors.New("token not authenticated according to TokenReview API")
	}

	namespace, serviceAccountName, err := k8s.GetNamesFromTokenStatus(tokenStatus)
	if err != nil {
		return fmt.Errorf("fail to parse username from token review status: %v", err)
	}
	fullServiceAccountName := fmt.Sprintf("%v:%v", namespace, serviceAccountName)

	if !cluster.serviceAccounts[fullServiceAccountName] {
		return fmt.Errorf("%q is not a whitelisted service account", fullServiceAccountName)
	}

	podName, err := k8s.GetPodNameFromTokenStatus(tokenStatus)
	if err != nil {
		return fmt.Errorf("fail to get pod name from token review status: %v", err)
	}

	podUID, err := k8s.GetPodUIDFromTokenStatus(tokenStatus)
	if err != nil {
		return fmt.Errorf("fail to get pod UID from token review status: %v", err)
	}

	pod, err := cluster.client.GetPod(namespace, podName)
	if err != nil {
		return fmt.Errorf("fail to get pod from k8s API server: %v", err)
	}

	node, err := cluster.client.GetNode(pod.Spec.NodeName)
	if err != nil {
		return fmt.Errorf("fail to get node from k8s API server: %v", err)
	}

	nodeUID := string(node.UID)
	if nodeUID == "" {
		return errors.New("node UID is empty")
	}

	selectors := []*spc.Selector{
		k8s.MakeSelector(pluginName, "cluster", attestationData.Cluster),
		k8s.MakeSelector(pluginName, "agent_ns", namespace),
		k8s.MakeSelector(pluginName, "agent_sa", serviceAccountName),
		k8s.MakeSelector(pluginName, "pod_name", podName),
		k8s.MakeSelector(pluginName, "agent_pod_uid", podUID),
		k8s.MakeSelector(pluginName, "agent_node_name", pod.Spec.NodeName),
		k8s.MakeSelector(pluginName, "agent_node_uid", nodeUID),
	}

	for key, value := range node.Labels {
		if cluster.allowedNodeLabelKeys[key] {
			selectors = append(selectors, k8s.MakeSelector(pluginName, "agent_node_label", key, value))
		}
	}

	for key, value := range pod.Labels {
		if cluster.allowedPodLabelKeys[key] {
			selectors = append(selectors, k8s.MakeSelector(pluginName, "agent_pod_label", key, value))
		}
	}

	return stream.Send(&nodeattestor.AttestResponse{
		AgentId:   p.agentID(pluginName, config.trustDomain, attestationData.Cluster, nodeUID, podUID),
		Selectors: selectors,
	})
}

func (p *K8sSidecarAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	hclConfig := new(K8sSidecarAttestorPluginConfig)
	if err := hcl.Decode(hclConfig, req.Configuration); err != nil {
		return nil, fmt.Errorf("unable to decode configuration: %v", err)
	}
	if req.GlobalConfig == nil {
		return nil, errors.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("global configuration missing trust domain")
	}

	if len(hclConfig.Clusters) == 0 {
		return nil, errors.New("configuration must have at least one cluster")
	}

	config := &attestorConfig{
		trustDomain: req.GlobalConfig.TrustDomain,
		clusters:    make(map[string]*clusterConfig),
	}

	for name, cluster := range hclConfig.Clusters {
		if len(cluster.ServiceAccountWhitelist) == 0 {
			return nil, fmt.Errorf("cluster %q configuration must have at least one service account whitelisted", name)
		}

		serviceAccounts := make(map[string]bool)
		for _, serviceAccount := range cluster.ServiceAccountWhitelist {
			serviceAccounts[serviceAccount] = true
		}

		var audience []string
		if cluster.Audience == nil {
			audience = defaultAudience
		} else {
			audience = *cluster.Audience
		}

		allowedNodeLabelKeys := make(map[string]bool)
		for _, label := range cluster.AllowedNodeLabelKeys {
			allowedNodeLabelKeys[label] = true
		}

		allowedPodLabelKeys := make(map[string]bool)
		for _, label := range cluster.AllowedPodLabelKeys {
			allowedPodLabelKeys[label] = true
		}

		config.clusters[name] = &clusterConfig{
			serviceAccounts:      serviceAccounts,
			audience:             audience,
			client:               apiserver.New(cluster.KubeConfigFile),
			allowedNodeLabelKeys: allowedNodeLabelKeys,
			allowedPodLabelKeys:  allowedPodLabelKeys,
		}
	}

	p.setConfig(config)
	return &spi.ConfigureResponse{}, nil
}

func (p *K8sSidecarAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *K8sSidecarAttestorPlugin) SetLogger(log hclog.Logger) {
	p.logger = log
}

func (p *K8sSidecarAttestorPlugin) getConfig() (*attestorConfig, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.config == nil {
		return nil, errors.New("not configured")
	}
	return p.config, nil
}

func (p *K8sSidecarAttestorPlugin) setConfig(config *attestorConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = config
}

func (p *K8sSidecarAttestorPlugin) agentID(pluginName, trustDomain, cluster, nodeID, podID string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", pluginName, cluster, nodeID, podID),
	}
	return u.String()
}

func main() {
	catalog.PluginMain(BuiltIn())
}
