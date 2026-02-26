package dashboard

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
)

var funcMap = template.FuncMap{
	"upper": strings.ToUpper,
}

var pageTmpls = map[string]*template.Template{
	"overview": template.Must(template.New("overview").Funcs(funcMap).Parse(navHTML + overviewHTML)),
	"audit":    template.Must(template.New("audit").Funcs(funcMap).Parse(navHTML + auditHTML)),
	"approval": template.Must(template.New("approval").Funcs(funcMap).Parse(navHTML + approvalHTML)),
	"policy":   template.Must(template.New("policy").Funcs(funcMap).Parse(navHTML + policyHTML)),
}

func renderPage(w http.ResponseWriter, name string, data map[string]any) {
	tmpl, ok := pageTmpls[name]
	if !ok {
		http.Error(w, "unknown page: "+name, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

const navHTML = `{{define "nav"}}
<nav class="bg-gray-900 border-b border-gray-700 px-6 py-4">
    <div class="flex items-center justify-between max-w-7xl mx-auto">
        <div class="flex items-center space-x-2">
            <span class="text-xl font-bold text-white">AgentGuard</span>
            <span class="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded">Dashboard</span>
        </div>
        <div class="flex space-x-4">
            <a href="/" class="px-3 py-2 rounded hover:bg-gray-800 {{if eq .Page "overview"}}bg-gray-800 text-white{{else}}text-gray-400{{end}}">Overview</a>
            <a href="/audit" class="px-3 py-2 rounded hover:bg-gray-800 {{if eq .Page "audit"}}bg-gray-800 text-white{{else}}text-gray-400{{end}}">Audit Log</a>
            <a href="/approval" class="px-3 py-2 rounded hover:bg-gray-800 {{if eq .Page "approval"}}bg-gray-800 text-white{{else}}text-gray-400{{end}}">Approvals</a>
            <a href="/policy" class="px-3 py-2 rounded hover:bg-gray-800 {{if eq .Page "policy"}}bg-gray-800 text-white{{else}}text-gray-400{{end}}">Policy</a>
        </div>
    </div>
</nav>
{{end}}`

const headHTML = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgentGuard Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@2.0.4"></script>
    <script src="https://unpkg.com/htmx-ext-sse@2.2.2/sse.js"></script>
    <style>body { background-color: #0f172a; color: #e2e8f0; }</style>
</head>
<body class="min-h-screen">
{{template "nav" .}}
<main class="max-w-7xl mx-auto px-6 py-8">`

const footHTML = `</main>
</body>
</html>`

const overviewHTML = headHTML + `
<h1 class="text-2xl font-bold mb-6">Overview</h1>
<div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
        <div class="text-gray-400 text-sm mb-1">Total Requests</div>
        <div class="text-3xl font-bold text-white">{{.Stats.TotalRequests}}</div>
    </div>
    <div class="bg-gray-900 border border-green-900 rounded-lg p-6">
        <div class="text-green-400 text-sm mb-1">Allowed</div>
        <div class="text-3xl font-bold text-green-300">{{.Stats.AllowCount}}</div>
    </div>
    <div class="bg-gray-900 border border-red-900 rounded-lg p-6">
        <div class="text-red-400 text-sm mb-1">Denied</div>
        <div class="text-3xl font-bold text-red-300">{{.Stats.DenyCount}}</div>
    </div>
    <div class="bg-gray-900 border border-yellow-900 rounded-lg p-6">
        <div class="text-yellow-400 text-sm mb-1">Pending Approval</div>
        <div class="text-3xl font-bold text-yellow-300">{{.Stats.AskCount}}</div>
    </div>
</div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">By Method</h2>
        {{range $method, $count := .Stats.ByMethod}}
        <div class="flex justify-between py-1 border-b border-gray-800">
            <span class="text-gray-300 font-mono text-sm">{{$method}}</span>
            <span class="text-gray-400">{{$count}}</span>
        </div>
        {{else}}<p class="text-gray-500">No data yet</p>{{end}}
    </div>
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
        <h2 class="text-lg font-bold mb-4">By Tool</h2>
        {{range $tool, $count := .Stats.ByTool}}
        <div class="flex justify-between py-1 border-b border-gray-800">
            <span class="text-gray-300 font-mono text-sm">{{$tool}}</span>
            <span class="text-gray-400">{{$count}}</span>
        </div>
        {{else}}<p class="text-gray-500">No data yet</p>{{end}}
    </div>
</div>
` + footHTML

const auditHTML = headHTML + `
<div class="flex justify-between items-center mb-6">
    <h1 class="text-2xl font-bold">Audit Log</h1>
    <span class="text-sm text-gray-400">Live updates via SSE</span>
</div>
<div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
    <table class="w-full text-sm text-left">
        <thead class="bg-gray-800 text-gray-400 uppercase text-xs">
            <tr>
                <th class="px-4 py-3">Time</th>
                <th class="px-4 py-3">Method</th>
                <th class="px-4 py-3">Tool</th>
                <th class="px-4 py-3">Arguments</th>
                <th class="px-4 py-3">Verdict</th>
                <th class="px-4 py-3">Rule</th>
            </tr>
        </thead>
        <tbody id="audit-table"
               hx-ext="sse"
               sse-connect="/audit/stream"
               sse-swap="audit"
               hx-swap="afterbegin">
            {{range .Records}}
            <tr class="border-b border-gray-700 hover:bg-gray-800">
                <td class="px-4 py-2 text-gray-400 text-xs">{{.Timestamp.Format "15:04:05"}}</td>
                <td class="px-4 py-2">{{.Method}}</td>
                <td class="px-4 py-2">{{.Tool}}</td>
                <td class="px-4 py-2 font-mono text-xs max-w-xs truncate">{{printf "%s" .Arguments}}</td>
                <td class="px-4 py-2">
                    {{if eq (printf "%s" .Verdict) "allow"}}<span class="px-2 py-1 rounded text-xs font-bold bg-green-900 text-green-300">ALLOW</span>
                    {{else if eq (printf "%s" .Verdict) "deny"}}<span class="px-2 py-1 rounded text-xs font-bold bg-red-900 text-red-300">DENY</span>
                    {{else if eq (printf "%s" .Verdict) "ask"}}<span class="px-2 py-1 rounded text-xs font-bold bg-yellow-900 text-yellow-300">ASK</span>
                    {{else}}<span class="px-2 py-1 rounded text-xs font-bold bg-blue-900 text-blue-300">LOG</span>{{end}}
                </td>
                <td class="px-4 py-2 text-gray-400 text-xs">{{.Rule}}</td>
            </tr>
            {{end}}
        </tbody>
    </table>
</div>
` + footHTML

const approvalHTML = headHTML + `
<h1 class="text-2xl font-bold mb-6">Approval Queue</h1>
{{if .Pending}}
<div class="space-y-4 mb-8">
    {{range .Pending}}
    <div class="bg-gray-900 border border-yellow-700 rounded-lg p-6">
        <div class="flex justify-between items-start">
            <div>
                <div class="text-yellow-400 text-xs font-bold mb-2">PENDING APPROVAL</div>
                <div class="text-white font-bold">{{.Method}}{{if .Tool}} / {{.Tool}}{{end}}</div>
                <div class="text-gray-400 text-sm mt-1">{{.Message}}</div>
                <div class="text-gray-500 text-xs mt-2">Rule: {{.Rule}} | Created: {{.CreatedAt.Format "15:04:05"}}</div>
                {{if .Arguments}}
                <div class="mt-2 bg-gray-800 rounded p-2 font-mono text-xs text-gray-300">{{printf "%s" .Arguments}}</div>
                {{end}}
            </div>
            <div class="flex space-x-2">
                <button hx-post="/approval/{{.ID}}/approve" hx-target="body"
                        class="px-4 py-2 bg-green-700 hover:bg-green-600 text-white rounded text-sm font-bold">Approve</button>
                <button hx-post="/approval/{{.ID}}/deny" hx-target="body"
                        class="px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded text-sm font-bold">Deny</button>
            </div>
        </div>
    </div>
    {{end}}
</div>
{{else}}
<div class="bg-gray-900 border border-gray-700 rounded-lg p-8 text-center text-gray-400">
    No pending approvals
</div>
{{end}}
` + footHTML

const policyHTML = headHTML + `
<h1 class="text-2xl font-bold mb-6">Active Policy</h1>
<div class="bg-gray-900 border border-gray-700 rounded-lg p-6">
    <pre class="font-mono text-sm text-gray-300 whitespace-pre-wrap">{{.PolicyYAML}}</pre>
</div>
` + footHTML
