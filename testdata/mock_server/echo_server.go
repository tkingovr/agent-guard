// echo_server.go is a minimal MCP server that echoes tool calls for testing.
// Usage: go run echo_server.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var msg jsonrpcMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			fmt.Fprintf(os.Stderr, "echo_server: invalid JSON: %v\n", err)
			continue
		}

		var resp jsonrpcMessage
		resp.JSONRPC = "2.0"
		resp.ID = msg.ID

		switch msg.Method {
		case "initialize":
			resp.Result = json.RawMessage(`{
				"protocolVersion": "2024-11-05",
				"capabilities": {"tools": {"listChanged": false}},
				"serverInfo": {"name": "echo-server", "version": "1.0.0"}
			}`)

		case "tools/list":
			resp.Result = json.RawMessage(`{
				"tools": [
					{
						"name": "read_file",
						"description": "Read a file",
						"inputSchema": {
							"type": "object",
							"properties": {"path": {"type": "string"}},
							"required": ["path"]
						}
					},
					{
						"name": "write_file",
						"description": "Write a file",
						"inputSchema": {
							"type": "object",
							"properties": {"path": {"type": "string"}, "content": {"type": "string"}},
							"required": ["path", "content"]
						}
					},
					{
						"name": "run_command",
						"description": "Run a shell command",
						"inputSchema": {
							"type": "object",
							"properties": {"command": {"type": "string"}},
							"required": ["command"]
						}
					}
				]
			}`)

		case "tools/call":
			// Echo back the params
			resp.Result, _ = json.Marshal(map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": fmt.Sprintf("echo: received tools/call with params: %s", string(msg.Params)),
					},
				},
			})

		case "ping":
			resp.Result = json.RawMessage(`{}`)

		case "notifications/initialized":
			// Notification, no response needed
			continue

		default:
			resp.Error = &jsonrpcError{
				Code:    -32601,
				Message: fmt.Sprintf("method not found: %s", msg.Method),
			}
		}

		data, _ := json.Marshal(resp)
		fmt.Println(string(data))
	}
}
