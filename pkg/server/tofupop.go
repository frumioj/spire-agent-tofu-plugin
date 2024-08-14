package server

import (
	"fmt"
	"context"
	"crypto/x509"
	"crypto/ed25519"
	"encoding/json"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/agentpathtemplate"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frumioj/spire-agent-tofu-plugin/pkg/common"	
)

const (
	pluginName = "x509pop"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

type configuration struct {
	trustDomain  spiffeid.TrustDomain
	trustBundle  *x509.CertPool
	pathTemplate *agentpathtemplate.Template
}

type Config struct {
	CABundlePath      string   `hcl:"ca_bundle_path"`
	CABundlePaths     []string `hcl:"ca_bundle_paths"`
	AgentPathTemplate string   `hcl:"agent_path_template"`
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	m      sync.Mutex
	config *configuration
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	config, err := p.getConfig()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	attestationData := new(common.AttestationData)
	if err := json.Unmarshal(payload, attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal data: %v", err)
	}

	candidatePubKey, err := x509.ParsePKIXPublicKey(attestationData.PublicKey)

	if err != nil {
		return status.Errorf(codes.Internal, "unable to retrieve candidate pub key: %v", err)
	}
	
	// now that the public key is trusted, issue a challenge to the node
	// to prove possession of the private key.

	// first cast it from any to the right type -- and hope that works? Perhaps need a switch here @@TODO
	
	pubkey := candidatePubKey.(*ed25519.PublicKey)
	
	challenge, err := common.GenerateChallenge(pubkey)
	
	if err != nil {
		return status.Errorf(codes.Internal, "unable to generate challenge: %v", err)
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challengeBytes,
		},
	}); err != nil {
		return err
	}

	// receive and validate the challenge response
	responseReq, err := stream.Recv()
	if err != nil {
		return err
	}

	response := new(common.Response)
	if err := json.Unmarshal(responseReq.GetChallengeResponse(), response); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshal challenge response: %v", err)
	}

	if err := common.VerifyChallengeResponse(candidatePubKey, challenge, response); err != nil {
		return status.Errorf(codes.PermissionDenied, "challenge response verification failed: %v", err)
	}

	// @@TODO: MakeAgentId needs to use the supplied public key to create a fingerprint for the ID or use the agent-supplied fingerprint hash
	spiffeid, err := common.MakeAgentID(config.trustDomain, config.pathTemplate, pubkey)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to make spiffe id: %v", err)
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       spiffeid.String(),
				SelectorValues: buildSelectorValues(pubkey),
				CanReattest:    true,
			},
		},
	})
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	hclConfig := new(Config)
	if err := hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}

	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "trust_domain is invalid: %v", err)
	}

	bundles, err := getBundles(hclConfig)
	if err != nil {
		return nil, err
	}

	pathTemplate := common.DefaultAgentPathTemplate
	if len(hclConfig.AgentPathTemplate) > 0 {
		tmpl, err := agentpathtemplate.Parse(hclConfig.AgentPathTemplate)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to parse agent svid template: %q", hclConfig.AgentPathTemplate)
		}
		pathTemplate = tmpl
	}

	p.setConfiguration(&configuration{
		trustDomain:  trustDomain,
		trustBundle:  util.NewCertPool(bundles...),
		pathTemplate: pathTemplate,
	})

	return &configv1.ConfigureResponse{}, nil
}

func getBundles(config *Config) ([]*x509.Certificate, error) {
	var caPaths []string

	switch {
	case config.CABundlePath != "" && len(config.CABundlePaths) > 0:
		return nil, status.Error(codes.InvalidArgument, "only one of ca_bundle_path or ca_bundle_paths can be configured, not both")
	case config.CABundlePath != "":
		caPaths = append(caPaths, config.CABundlePath)
	case len(config.CABundlePaths) > 0:
		caPaths = append(caPaths, config.CABundlePaths...)
	default:
		return nil, status.Error(codes.InvalidArgument, "ca_bundle_path or ca_bundle_paths must be configured")
	}

	var cas []*x509.Certificate
	for _, caPath := range caPaths {
		certs, err := util.LoadCertificates(caPath)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "unable to load trust bundle %q: %v", caPath, err)
		}
		cas = append(cas, certs...)
	}

	return cas, nil
}

func (p *Plugin) getConfig() (*configuration, error) {
	p.m.Lock()
	defer p.m.Unlock()
	if p.config == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *Plugin) setConfiguration(config *configuration) {
	p.m.Lock()
	defer p.m.Unlock()
	p.config = config
}

func buildSelectorValues(pubkey *ed25519.PublicKey) []string {
	var selectorValues []string

	fprint := common.Fingerprint(pubkey)

	if fprint == "" {
		fmt.Println("Could not fingerprint the public key!")
		return nil
	}
	
	selectorValues = append(selectorValues, "subject:pk:"+fprint)

	return selectorValues
}
