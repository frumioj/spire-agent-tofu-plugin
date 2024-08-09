package main

import (
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"

	"github.com/frumioj/spire-agent-tofu-plugin/pkg/server"
)

func main() {
	p := agent.New()
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
