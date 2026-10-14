package db

import "testing"

func rule(kind, pattern string, enabled bool) AssetInterceptRule {
	return AssetInterceptRule{Kind: kind, Pattern: pattern, Enabled: enabled}
}

func TestMatchAssetInterceptRules(t *testing.T) {
	cases := []struct {
		name    string
		rules   []AssetInterceptRule
		domains []string
		ips     []string
		urls    []string
		want    bool
		wantVal string
	}{
		{"built-in fuzzy government domain hit", []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
			[]string{"www.beijing.gov.cn"}, nil, nil, true, "www.beijing.gov.cn"},
		{"fuzzy education domain hit", []AssetInterceptRule{rule("fuzzy_domain", ".edu", true)},
			[]string{"mit.edu"}, nil, nil, true, "mit.edu"},
		{"exact domain hit case-insensitive", []AssetInterceptRule{rule("exact_domain", "Example.com", true)},
			[]string{"example.com"}, nil, nil, true, "example.com"},
		{"exact domain does not match subdomain", []AssetInterceptRule{rule("exact_domain", "example.com", true)},
			[]string{"a.example.com"}, nil, nil, false, ""},
		{"exact IP hit", []AssetInterceptRule{rule("exact_ip", "203.0.113.5", true)},
			nil, []string{"203.0.113.5"}, nil, true, "203.0.113.5"},
		{"fuzzy IP prefix hit", []AssetInterceptRule{rule("fuzzy_ip", "203.0.113.", true)},
			nil, []string{"203.0.113.99"}, nil, true, "203.0.113.99"},
		{"CIDR hit", []AssetInterceptRule{rule("cidr", "192.168.0.0/16", true)},
			nil, []string{"192.168.5.20"}, nil, true, "192.168.5.20"},
		{"CIDR miss", []AssetInterceptRule{rule("cidr", "192.168.0.0/16", true)},
			nil, []string{"10.0.0.1"}, nil, false, ""},
		{"exact URL hit", []AssetInterceptRule{rule("exact_url", "https://a.gov.cn/login", true)},
			nil, nil, []string{"https://a.gov.cn/login"}, true, "https://a.gov.cn/login"},
		{"fuzzy URL hit path", []AssetInterceptRule{rule("fuzzy_url", "/admin", true)},
			nil, nil, []string{"https://x.com/admin/panel"}, true, "https://x.com/admin/panel"},
		{"disabled rule does not match", []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", false)},
			[]string{"www.gov.cn"}, nil, nil, false, ""},
		{"no rules no match", nil, []string{"www.gov.cn"}, nil, nil, false, ""},
		{"empty pattern no match", []AssetInterceptRule{rule("fuzzy_domain", "  ", true)},
			[]string{"www.gov.cn"}, nil, nil, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, val, ok := MatchAssetInterceptRules(c.rules, c.domains, c.ips, c.urls)
			if ok != c.want {
				t.Fatalf("hit = %v, want %v (rule=%+v)", ok, c.want, r)
			}
			if ok && val != c.wantVal {
				t.Fatalf("hit value = %q, want %q", val, c.wantVal)
			}
		})
	}
}

func TestEvaluateAssetGate(t *testing.T) {
	block := []AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)}
	allow := []AssetInterceptRule{rule("fuzzy_domain", "example.com", true)}

	// 1. Matches a block rule → reject (block reason takes priority).
	if d := EvaluateAssetGate(block, allow, []string{"www.gov.cn"}, nil, nil); d.Allowed {
		t.Fatal("matching a block rule should be rejected")
	}

	// 2. No block hit, allow rules exist but none match → reject (not allowed).
	d := EvaluateAssetGate(block, allow, []string{"foo.other.com"}, nil, nil)
	if d.Allowed {
		t.Fatal("whitelist present and no hit should be rejected")
	}
	if d.Reason == "" {
		t.Fatal("a rejection should carry a reason")
	}

	// 3. No block hit, allow rule matches → pass.
	if d := EvaluateAssetGate(block, allow, []string{"api.example.com"}, nil, nil); !d.Allowed {
		t.Fatal("matching the whitelist should pass")
	}

	// 4. No allow rules (whitelist not enabled) → passes as long as there is no block hit.
	if d := EvaluateAssetGate(block, nil, []string{"foo.other.com"}, nil, nil); !d.Allowed {
		t.Fatal("with no whitelist, no block hit should pass")
	}

	// 5. All allow rules disabled → treated as whitelist not enabled, pass.
	disabledAllow := []AssetInterceptRule{rule("fuzzy_domain", "example.com", false)}
	if d := EvaluateAssetGate(nil, disabledAllow, []string{"foo.other.com"}, nil, nil); !d.Allowed {
		t.Fatal("when all whitelist rules are disabled it should pass")
	}

	// 6. Block takes priority over allow: a target that matches both block and allow → reject.
	if d := EvaluateAssetGate(
		[]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
		[]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)},
		[]string{"www.gov.cn"}, nil, nil,
	); d.Allowed {
		t.Fatal("block should take priority over allow")
	}
}

func TestAssetInterceptCandidates(t *testing.T) {
	// URL-only service asset: the host should be split out into the domain candidates so fuzzy_domain matches it.
	a := &Asset{Type: "service", URL: "https://portal.beijing.gov.cn:8443/app"}
	domains, _, urls := a.interceptCandidates()
	if len(urls) != 1 || urls[0] != a.URL {
		t.Fatalf("urls = %v", urls)
	}
	found := false
	for _, d := range domains {
		if d == "portal.beijing.gov.cn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("URL host not split into domain candidates: %v", domains)
	}
	r, _, ok := MatchAssetInterceptRules([]AssetInterceptRule{rule("fuzzy_domain", ".gov.cn", true)}, domains, nil, urls)
	if !ok {
		t.Fatalf("a URL-only government service asset should be matched by fuzzy_domain, rule=%+v", r)
	}

	// When the URL host is an IP it should go into the IP candidates and be matchable by CIDR.
	b := &Asset{Type: "service", URL: "http://10.1.2.3/x"}
	_, ips, _ := b.interceptCandidates()
	if r, _, ok := MatchAssetInterceptRules([]AssetInterceptRule{rule("cidr", "10.0.0.0/8", true)}, nil, ips, nil); !ok {
		t.Fatalf("the IP in the URL should be matched by CIDR, ips=%v rule=%+v", ips, r)
	}
}
