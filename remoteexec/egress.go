package remoteexec

// EgressEnv builds the Bash-subprocess environment that routes child-command HTTP
// through an egress proxy and, when a CA is given, makes the common toolchain trust
// it (so curl/nmap/python need no -x/-k). It mirrors the monolith's agent.proxyEnv,
// but lives here because it runs on the Agent — the control plane no longer sets Bash
// egress; the sandbox does, pointing at its own local recording proxy.
//
// Empty proxyAddr returns nil (direct egress, unchanged environment).
func EgressEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"ALL_PROXY=" + proxyAddr, "all_proxy=" + proxyAddr,
		"NODE_USE_ENV_PROXY=1",
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}
