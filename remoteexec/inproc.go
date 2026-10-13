package remoteexec

import "net"

// InProcess wires an Agent Executor to a Management-side Session over an in-memory
// net.Pipe — no sockets, no TLS. It powers the all-in-one deployment (Management and
// Agent in one process) and the tests: the same Session/Executor/RemoteBackend code
// path as the networked split, so the two deployments cannot diverge.
//
// The returned Session is the Management (caller) side; it is also returned wrapped as
// a ready RemoteBackend for convenience. closeFn tears both sides down.
func InProcess(exec *Executor) (mgmt *Session, backend *RemoteBackend, closeFn func()) {
	a, b := net.Pipe()
	agentSess := newSession(a, "agent", exec)
	mgmtSess := newSession(b, "mgmt", nil)
	agentSess.sendHello("in-process", exec.ToolNames())
	backend = NewRemoteBackend(mgmtSess, exec.ToolNames())
	closeFn = func() {
		mgmtSess.Close()
		agentSess.Close()
	}
	return mgmtSess, backend, closeFn
}
