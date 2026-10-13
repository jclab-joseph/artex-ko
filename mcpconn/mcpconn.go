// Package mcpconn is a db-free MCP connection helper shared by the control plane and
// the sandboxed Agent. It dispatches a transport-agnostic Config to the right client
// (stdio via norma/mcp, Streamable HTTP / legacy SSE via mcphttp) and exposes the
// common tools/list + close surface. Keeping it free of the artex `db` package is what
// lets the Agent binary host MCP servers without ever linking the control-plane DB.
package mcpconn

import (
	"context"
	"errors"
	"fmt"

	"github.com/Autumn-27/artex/mcphttp"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

// Config is one MCP server's connection info in parsed (db-free) form. Env doubles as
// HTTP headers (e.g. {"Authorization":"Bearer …"}) for the http/sse transports.
type Config struct {
	Name      string            `json:"name"`
	Transport string            `json:"transport"`
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	URL       string            `json:"url,omitempty"`
	Insecure  bool              `json:"insecure,omitempty"`
}

// Client is the shared surface of a connected MCP server regardless of transport.
type Client interface {
	Tools(context.Context) ([]actool.CoreTool, error)
	Close() error
}

// Connect dials an MCP server per its transport. stdio spawns a child process (which,
// on the Agent, runs inside the sandbox); http/sse connect out to a URL.
func Connect(ctx context.Context, c Config) (Client, error) {
	switch c.Transport {
	case "stdio":
		if c.Command == "" {
			return nil, errors.New("mcpconn: stdio transport requires a command")
		}
		return mcp.NewStdioClient(ctx, c.Name, c.Command, c.Env, c.Args...)
	case "http":
		if c.URL == "" {
			return nil, errors.New("mcpconn: http transport requires a url")
		}
		return mcphttp.New(ctx, c.Name, c.URL, c.Env, c.Insecure)
	case "sse":
		if c.URL == "" {
			return nil, errors.New("mcpconn: sse transport requires a url")
		}
		return mcphttp.NewSSE(ctx, c.Name, c.URL, c.Env, c.Insecure)
	default:
		return nil, fmt.Errorf("mcpconn: unknown transport %q", c.Transport)
	}
}
