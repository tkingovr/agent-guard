package stdio

import (
	"fmt"
	"io"
	"os/exec"
)

// Process wraps a subprocess with access to its stdin/stdout.
type Process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

// StartProcess launches the MCP server subprocess and returns handles to its pipes.
func StartProcess(name string, args []string) (*Process, error) {
	cmd := exec.Command(name, args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	// Let stderr pass through to our stderr
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting subprocess %q: %w", name, err)
	}

	return &Process{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
	}, nil
}

// Wait waits for the subprocess to exit.
func (p *Process) Wait() error {
	return p.cmd.Wait()
}

// Kill terminates the subprocess.
func (p *Process) Kill() error {
	if p.cmd.Process != nil {
		return p.cmd.Process.Kill()
	}
	return nil
}

// Stdin returns the write end of the subprocess stdin.
func (p *Process) Stdin() io.WriteCloser { return p.stdin }

// Stdout returns the read end of the subprocess stdout.
func (p *Process) Stdout() io.ReadCloser { return p.stdout }
