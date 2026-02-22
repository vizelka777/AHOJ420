package auth

import "testing"

func TestSafePostLogoutRedirect(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{name: "houbamzdar root", in: "https://houbamzdar.cz/", out: "https://houbamzdar.cz/"},
		{name: "houbamzdar index", in: "https://houbamzdar.cz/index.html", out: "https://houbamzdar.cz/index.html"},
		{name: "localhost", in: "http://localhost:3000/", out: "http://localhost:3000/"},
		{name: "loopback", in: "http://127.0.0.1:3000/", out: "http://127.0.0.1:3000/"},
		{name: "external rejected", in: "https://evil.example/", out: "https://ahoj420.eu/"},
		{name: "empty default", in: "", out: "https://ahoj420.eu/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := safePostLogoutRedirect(tc.in); got != tc.out {
				t.Fatalf("safePostLogoutRedirect(%q)=%q want %q", tc.in, got, tc.out)
			}
		})
	}
}
