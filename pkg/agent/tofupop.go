package agent

import (
	"fmt"
	"net"
	"context"
	"crypto"
	"encoding/json"
	"sync"
	"runtime"
	"io/ioutil"
	"os/user"
	"encoding/pem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/ed25519"
	"crypto/x509"
	
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frumioj/spire-agent-tofu-plugin/pkg/common"
)

const (
	pluginName = "tofupop"
)

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p))
}

type configData struct {
	privateKey         crypto.PrivateKey
	attestationPayload []byte
	// probably want to put a signed CSR in here one day
}

type Config struct {
	PrivateKeyPath    string `hcl:"private_key_path"`
}

type Plugin struct {
	nodeattestorv1.UnsafeNodeAttestorServer
	configv1.UnsafeConfigServer

	m sync.Mutex
	c *Config
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) (err error) {
	data, err := p.loadConfigData()
	if err != nil {
		return err
	}

	// send the attestation data back to the server
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: data.attestationPayload,
		},
	}); err != nil {
		return err
	}

	// receive challenge
	resp, err := stream.Recv()
	if err != nil {
		return err
	}

	challenge := new(common.Challenge)
	if err := json.Unmarshal(resp.Challenge, challenge); err != nil {
		return status.Errorf(codes.Internal, "unable to unmarshal challenge: %v", err)
	}

	// calculate and send the challenge response
	response, err := common.CalculateResponse(data.privateKey, challenge)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to calculate challenge response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenge response: %v", err)
	}

	return stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: responseBytes,
		},
	})
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.PrivateKeyPath == "" {
		return nil, status.Error(codes.InvalidArgument, "private_key_path is required")
	}

	// make sure the configuration produces valid data
	if _, err := loadConfigData(config); err != nil {
		return nil, err
	}

	p.setConfig(config)

	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) getConfig() *Config {
	p.m.Lock()
	defer p.m.Unlock()
	return p.c
}

func (p *Plugin) setConfig(c *Config) {
	p.m.Lock()
	defer p.m.Unlock()
	p.c = c
}

// Stays the same as for x509
func (p *Plugin) loadConfigData() (*configData, error) {
	config := p.getConfig()
	if config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return loadConfigData(config)
}

func platform() (string){
	return runtime.GOOS + " " + runtime.GOARCH
}

func uid() (string){

	usr, err := user.Current()

	if err != nil {
		fmt.Printf("Error returning UID: %v", err.Error)
		return "0"
	}
	
	return usr.Uid
}

func localAddresses() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
			continue
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPAddr:
				fmt.Printf("%v : %s (%s)\n", i.Name, v, v.IP.DefaultMask())
				
			case *net.IPNet:
				fmt.Printf("%v : %s [%v/%v]\n", i.Name, v, v.IP, v.Mask)
			}
			
		}
	}
}

func fingerprint() ([32]byte) {
	platform := runtime.GOOS + " " + runtime.GOARCH
	usr, err := user.Current()
	uid := "0"
	output := ""
	
	if err != nil {
		fmt.Printf("Error returning UID: %v\n", err.Error)
	}
	
	uid = usr.Uid

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
	}
	if ifaces != nil {
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			addr := ""
			if err != nil {
				fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
				continue
			}
			for _, a := range addrs {
				switch v := a.(type) {
				case *net.IPAddr:
					addr = fmt.Sprintf("%v : %s (%s)", i.Name, v, v.IP.DefaultMask())
					
				case *net.IPNet:
					addr = fmt.Sprintf("%v : %s [%v/%v]", i.Name, v, v.IP, v.Mask)
				}
				
				output = output + addr
				
			}
		}
	}
	
	return sha256.Sum256([]byte(output + platform + uid))
}

func generateKey(path string) (priv ed25519.PrivateKey, err error){

	var (
		b     []byte
		block *pem.Block
		pub   ed25519.PublicKey
	)

	pub, priv, err = ed25519.GenerateKey(rand.Reader)

	if err != nil {
		fmt.Printf("Generation error : %s", err)
		return nil, err
	}
	
	b, err = x509.MarshalPKCS8PrivateKey(priv)
	
	if err != nil {
		return nil, err
	}

	block = &pem.Block{
		Type:  "SPIRE AGENT PRIVATE KEY",
		Bytes: b,
	}

	fileName := path + "key.priv"
	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0600)
	if err != nil {
		return nil, err
	}

	// public key
	b, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	block = &pem.Block{
		Type:  "SPIRE AGENT PUBLIC KEY",
		Bytes: b,
	}

	fileName = path + "key.pub"
	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0644)
	return priv, err
}

func sign(data []byte, key ed25519.PrivateKey) ([]byte, error){
	sig, err := key.Sign(nil, data, &ed25519.Options{Context: "SPIRE AGENT NODE ATTESTATION"})

	if err != nil {
		fmt.Printf("Signature failed: %s", err.Error)
		return nil, err
	}

	return sig, nil
}

func loadKey(path string) (ed25519.PrivateKey, error){
	privBytes, err := ioutil.ReadFile(path + "key.priv")
	
	if err != nil {
		fmt.Println("No private key found")
		return nil, err
	}

	block, _ := pem.Decode(privBytes)
	
	candidatePrivate, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	
	if err != nil {
		fmt.Printf("Error parsing key: %s", err.Error)
		return nil, err
	}

	fmt.Printf("PRIV: %v", candidatePrivate)
	priv := candidatePrivate.(ed25519.PrivateKey)
	
	return priv, nil
}

// @@TODO: configData should contain
// 1. File path to store private key if needed
// 2. Items to include in a fingerprint of the device(?)
// 3. A CSR signed with the generated key?

func loadConfigData(config *Config) (*configData, error) {

	// if the key at path exists then load the private key
	// else create it at that path

	var priv ed25519.PrivateKey = nil
	var err error = nil
	
	priv, err = loadKey(config.PrivateKeyPath)

	if err != nil {
		return nil, err
	}

	finger := fingerprint() 
	fmt.Printf("fingerprint: %x", finger)

	if err != nil {
		fmt.Printf("Error generating key: %s", err.Error)
		return nil, err
	}

	if priv != nil {
		signature, err := sign(finger[:], priv)

		if err != nil {
			fmt.Printf("Signature failed for: %s\n", err.Error)
		}
		
		fmt.Printf("Signed fingerprint: %x", signature)

		pub, err := x509.MarshalPKIXPublicKey(priv.Public())

		if err != nil {
			fmt.Printf("Could not get public key: %s\n", err.Error)
		}
		
		attestationPayload, err := json.Marshal(common.AttestationData{
			Fingerprint: finger,
			Signature: signature,
			PublicKey: pub,
		})
	
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
		}

		return &configData{
			privateKey:         priv,
			attestationPayload: attestationPayload,
		}, nil
	}

	return nil, err
}
