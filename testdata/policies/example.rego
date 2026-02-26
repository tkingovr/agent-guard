package agentguard

import rego.v1

default verdict := "deny"

default rule_name := "_default"

default message := "no matching rule; default deny"

# Allow protocol handshake
verdict := "allow" if {
	input.method == "initialize"
}

rule_name := "allow-initialize" if {
	input.method == "initialize"
}

# Allow tool listing
verdict := "allow" if {
	input.method == "tools/list"
}

rule_name := "allow-tools-list" if {
	input.method == "tools/list"
}

# Allow ping
verdict := "allow" if {
	input.method == "ping"
}

rule_name := "allow-ping" if {
	input.method == "ping"
}

# Block SSH key access
verdict := "deny" if {
	input.method == "tools/call"
	some key, val in input.arguments
	contains(val, ".ssh/")
}

rule_name := "block-ssh-keys" if {
	input.method == "tools/call"
	some key, val in input.arguments
	contains(val, ".ssh/")
}

message := "SSH key access blocked" if {
	input.method == "tools/call"
	some key, val in input.arguments
	contains(val, ".ssh/")
}

# Allow read_file tool
verdict := "allow" if {
	input.method == "tools/call"
	input.tool == "read_file"
	not ssh_key_access
}

rule_name := "allow-read-file" if {
	input.method == "tools/call"
	input.tool == "read_file"
	not ssh_key_access
}

# Require approval for write_file
verdict := "ask" if {
	input.method == "tools/call"
	input.tool == "write_file"
	not ssh_key_access
}

rule_name := "ask-write-file" if {
	input.method == "tools/call"
	input.tool == "write_file"
	not ssh_key_access
}

message := "File write requires approval" if {
	input.method == "tools/call"
	input.tool == "write_file"
	not ssh_key_access
}

# Helper rule
ssh_key_access if {
	some key, val in input.arguments
	contains(val, ".ssh/")
}
