// Command mcpstub is a minimal stdio MCP server for the execution-plane e2e: it
// speaks just enough of the MCP JSON-RPC protocol (line-delimited over stdio) for
// norma/mcp's client to handshake, list one tool ("echo"), and call it. It exists so
// the sandboxed Agent can host a REAL MCP server in the e2e and Management can drive
// its tool over the channel — proving the Agent-hosted MCP path end to end.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	out := bufio.NewWriter(os.Stdout)

	write := func(id json.RawMessage, result any) {
		resp := map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
		b, _ := json.Marshal(resp)
		out.Write(b)
		out.WriteByte('\n')
		out.Flush()
	}

	for in.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			write(req.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "mcpstub", "version": "0.1"},
			})
		case "notifications/initialized":
			// notification: no response
		case "tools/list":
			write(req.ID, map[string]any{
				"tools": []any{
					map[string]any{
						"name":        "echo",
						"description": "echo back the given text",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{"text": map[string]any{"type": "string"}},
							"required":   []any{"text"},
						},
					},
				},
			})
		case "tools/call":
			var p struct {
				Name      string `json:"name"`
				Arguments struct {
					Text string `json:"text"`
				} `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &p)
			write(req.ID, map[string]any{
				"content": []any{
					map[string]any{"type": "text", "text": fmt.Sprintf("mcp-echo:%s", p.Arguments.Text)},
				},
				"isError": false,
			})
		default:
			if len(req.ID) > 0 {
				write(req.ID, map[string]any{})
			}
		}
	}
}
