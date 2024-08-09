build: cmd/agent/tofupop/tofupop_agent.go cmd/server/tofupop/tofupop_server.go
	GOOS=linux GOARCH=amd64 go build -o tofupop_agent cmd/agent/tofupop/tofupop_agent.go
	GOOS=linux GOARCH=amd64 go build -o tofupop_server cmd/server/tofupop/tofupop_server.go
