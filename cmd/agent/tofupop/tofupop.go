package main

import (
	"github.com/frumioj/spire-agent-tofu-plugin/pkg/agent"
	"github.com/frumioj/spire-agent-tofu-plugin/pkg/common"
	"github.com/spiffe/spire/pkg/agent/plugin/nodeattestor"
	"github.com/spiffe/spire/pkg/common/catalog"
)

func main() {
	p := agent.New()
	catalog.PluginMain(
		catalog.MakePlugin(common.PluginName, nodeattestor.PluginServer(p)),
	)
}
