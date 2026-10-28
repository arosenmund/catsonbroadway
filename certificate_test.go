package main

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGenerateCertificateWithIndependentIssuer(t *testing.T) {
	for _, keyType := range []string{"rsa", "ecdsa", "ed25519"} {
		t.Run(keyType, func(t *testing.T) {
			certificateTestDirectory(t)
			config := certificateTestConfig(keyType)
			config.Issuer = &CertificateNameConfig{
				CommonName:         "Example Test Signing CA",
				Organization:       "Example Issuer Organization",
				OrganizationalUnit: "Certificate Services",
				Country:            "GB",
				Province:           "Issuer Province",
				Locality:           "Issuer City",
			}

			info, err := generateCertificate(&config)
			if err != nil {
				t.Fatalf("generateCertificate() error = %v", err)
			}
			if info.SelfSigned || !info.LocalCA {
				t.Fatalf("certificate info = %+v, want local CA and not self-signed", info)
			}
			certificates := readGeneratedCertificates(t)
			if len(certificates) != 2 {
				t.Fatalf("certificate count = %d, want leaf followed by CA", len(certificates))
			}
			leaf, issuer := certificates[0], certificates[1]
			assertCertificateName(t, leaf.Subject, pkix.Name{
				CommonName:         config.CommonName,
				Organization:       []string{config.Organization},
				OrganizationalUnit: []string{config.OrganizationalUnit},
				Country:            []string{config.Country},
				Province:           []string{config.Province},
				Locality:           []string{config.Locality},
			})
			assertCertificateName(t, leaf.Issuer, pkix.Name{
				CommonName:         config.Issuer.CommonName,
				Organization:       []string{config.Issuer.Organization},
				OrganizationalUnit: []string{config.Issuer.OrganizationalUnit},
				Country:            []string{config.Issuer.Country},
				Province:           []string{config.Issuer.Province},
				Locality:           []string{config.Issuer.Locality},
			})
			if !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) {
				t.Fatal("leaf issuer does not match the signing CA subject")
			}
			if bytes.Equal(leaf.RawSubjectPublicKeyInfo, issuer.RawSubjectPublicKeyInfo) {
				t.Fatal("leaf and signing CA share a public key")
			}
			if leaf.IsCA || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
				t.Fatal("expected a server leaf and a signing CA")
			}
			if err := leaf.CheckSignatureFrom(issuer); err != nil {
				t.Fatalf("leaf signature verification: %v", err)
			}
			if err := issuer.CheckSignatureFrom(issuer); err != nil {
				t.Fatalf("root signature verification: %v", err)
			}
			if !reflect.DeepEqual(leaf.DNSNames, []string{"files.example.test"}) || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" {
				t.Fatalf("SANs changed: DNS = %v, IP = %v", leaf.DNSNames, leaf.IPAddresses)
			}
			verifyOptions := x509.VerifyOptions{
				Roots:       x509.NewCertPool(),
				DNSName:     "files.example.test",
				CurrentTime: leaf.NotBefore.Add(time.Hour),
			}
			if _, err := leaf.Verify(verifyOptions); err == nil {
				t.Fatal("leaf unexpectedly verified without trusting the generated CA")
			}
			verifyOptions.Roots.AddCert(issuer)
			if _, err := leaf.Verify(verifyOptions); err != nil {
				t.Fatalf("leaf verification with explicit CA trust: %v", err)
			}
			pair, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
			if err != nil {
				t.Fatalf("TLS certificate/key loading: %v", err)
			}
			if len(pair.Certificate) != 2 {
				t.Fatalf("TLS chain length = %d, want 2", len(pair.Certificate))
			}
			keyPEM, err := os.ReadFile("key.pem")
			if err != nil {
				t.Fatal(err)
			}
			block, remainder := pem.Decode(keyPEM)
			if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(remainder)) != 0 {
				t.Fatal("key.pem must contain exactly one PKCS8 private key")
			}
			if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				t.Fatalf("PKCS8 private key parsing: %v", err)
			}
			files, err := os.ReadDir(".")
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 2 {
				t.Fatalf("generated %d files, want only cert.pem and key.pem", len(files))
			}
		})
	}
}

func TestGenerateCertificateWithoutIssuerRemainsSelfSigned(t *testing.T) {
	certificateTestDirectory(t)
	config := certificateTestConfig("ed25519")
	info, err := generateCertificate(&config)
	if err != nil {
		t.Fatal(err)
	}
	if !info.SelfSigned || info.LocalCA {
		t.Fatalf("certificate info = %+v, want self-signed", info)
	}
	certificates := readGeneratedCertificates(t)
	if len(certificates) != 1 {
		t.Fatalf("certificate count = %d, want 1", len(certificates))
	}
	cert := certificates[0]
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		t.Fatal("legacy issuer differs from subject")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("self-signature verification: %v", err)
	}
	if _, err := tls.LoadX509KeyPair("cert.pem", "key.pem"); err != nil {
		t.Fatalf("TLS certificate/key loading: %v", err)
	}
}

func TestGenerateCertificatePartialIssuerDoesNotInheritSubject(t *testing.T) {
	certificateTestDirectory(t)
	config := certificateTestConfig("ecdsa")
	config.Issuer = &CertificateNameConfig{CommonName: "Separate Local CA"}
	if _, err := generateCertificate(&config); err != nil {
		t.Fatal(err)
	}
	certificates := readGeneratedCertificates(t)
	if len(certificates) != 2 {
		t.Fatalf("certificate count = %d, want 2", len(certificates))
	}
	assertCertificateName(t, certificates[0].Issuer, pkix.Name{CommonName: "Separate Local CA"})
	assertCertificateName(t, certificates[1].Subject, pkix.Name{CommonName: "Separate Local CA"})
}

func TestGenerateCertificatePreservesCAWithIndependentIssuer(t *testing.T) {
	certificateTestDirectory(t)
	config := certificateTestConfig("ed25519")
	config.IsCA = true
	config.Issuer = &CertificateNameConfig{CommonName: "Example Root CA"}
	if _, err := generateCertificate(&config); err != nil {
		t.Fatal(err)
	}
	certificates := readGeneratedCertificates(t)
	if len(certificates) != 2 {
		t.Fatalf("certificate count = %d, want 2", len(certificates))
	}
	subordinate, root := certificates[0], certificates[1]
	if !subordinate.IsCA || subordinate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("is_ca did not preserve the generated certificate's signing capability")
	}
	keyPEM, err := os.ReadFile("key.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("key.pem contains no PEM key")
	}
	signingKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	childPublicKey, _, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	childTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "child.example.test"},
		DNSNames:     []string{"child.example.test"},
		NotBefore:    subordinate.NotBefore,
		NotAfter:     subordinate.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	childDER, err := x509.CreateCertificate(crand.Reader, &childTemplate, subordinate, childPublicKey, signingKey)
	if err != nil {
		t.Fatalf("sign child certificate: %v", err)
	}
	child, err := x509.ParseCertificate(childDER)
	if err != nil {
		t.Fatal(err)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(subordinate)
	if _, err := child.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "child.example.test",
		CurrentTime:   subordinate.NotBefore.Add(time.Hour),
	}); err != nil {
		t.Fatalf("verify child through generated intermediate and root: %v", err)
	}
}

func TestLoadCertConfigPreservesSeparateIssuer(t *testing.T) {
	first := certificateTestConfig("ecdsa")
	first.Issuer = &CertificateNameConfig{CommonName: "First Issuer", Organization: "First Issuer Organization"}
	second := certificateTestConfig("ed25519")
	second.Issuer = &CertificateNameConfig{CommonName: "Second Issuer", Organization: "Second Issuer Organization"}
	profiles := CertProfileConfig{DefaultProfile: "first", Profiles: map[string]CertConfig{"first": first, "second": second}}
	for _, test := range []struct {
		name    string
		data    any
		profile string
		want    CertConfig
	}{
		{name: "default profile", data: profiles, want: first},
		{name: "requested profile", data: profiles, profile: "second", want: second},
		{name: "legacy flat", data: first, want: first},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.data)
			if err != nil {
				t.Fatal(err)
			}
			path := writeTempFile(t, "cert_config.json", string(data))
			got, _, err := loadCertConfig(path, test.profile)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(*got, test.want) {
				t.Fatalf("loaded config = %+v, want %+v", *got, test.want)
			}
		})
	}
	for _, data := range []string{`{"common_name":"legacy.example.test"}`, `{"common_name":"legacy.example.test","issuer":null}`} {
		path := writeTempFile(t, "cert_config.json", data)
		got, _, err := loadCertConfig(path, "")
		if err != nil {
			t.Fatal(err)
		}
		if got.Issuer != nil {
			t.Fatalf("legacy config issuer = %+v, want nil", got.Issuer)
		}
	}
}

func TestLoadCertConfigRejectsMalformedIssuerTypes(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{"profile issuer string", `{"default_profile":"test","profiles":{"test":{"common_name":"files.example.test","issuer":"Example CA"}}}`},
		{"profile issuer numeric field", `{"default_profile":"test","profiles":{"test":{"common_name":"files.example.test","issuer":{"common_name":42}}}}`},
		{"flat issuer string", `{"common_name":"files.example.test","issuer":"Example CA"}`},
		{"flat issuer numeric field", `{"common_name":"files.example.test","issuer":{"common_name":42}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeTempFile(t, "cert_config.json", test.data)
			if _, _, err := loadCertConfig(path, ""); err == nil || !strings.Contains(err.Error(), "issuer") {
				t.Fatalf("loadCertConfig() error = %v, want issuer type error", err)
			}
		})
	}
}

func TestEmptyIssuerIsRejectedBeforeWritingCertificates(t *testing.T) {
	for _, issuer := range []*CertificateNameConfig{{}, {CommonName: " \t", Organization: "\n"}} {
		t.Run("empty issuer", func(t *testing.T) {
			certificateTestDirectory(t)
			config := certificateTestConfig("ecdsa")
			config.Issuer = issuer
			for _, data := range []any{config, CertProfileConfig{DefaultProfile: "test", Profiles: map[string]CertConfig{"test": config}}} {
				encoded, err := json.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
				path := writeTempFile(t, "cert_config.json", string(encoded))
				if _, _, err := loadCertConfig(path, ""); err == nil || !strings.Contains(err.Error(), "issuer") {
					t.Fatalf("loadCertConfig() error = %v, want issuer validation error", err)
				}
			}
			for _, path := range []string{"cert.pem", "key.pem"} {
				if err := os.WriteFile(path, []byte("existing file"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := generateCertificate(&config); err == nil || !strings.Contains(err.Error(), "issuer") {
				t.Fatalf("generateCertificate() error = %v, want issuer validation error", err)
			}
			for _, path := range []string{"cert.pem", "key.pem"} {
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "existing file" {
					t.Fatalf("%s changed after invalid issuer: contents = %q, error = %v", path, data, err)
				}
			}
		})
	}
}

func TestRenderDownloadCommandsLocalCAIncludesCertificateBypass(t *testing.T) {
	commands := renderDownloadCommands(DownloadCommandOptions{
		URL:         "https://files.example.test/download",
		OutputFile:  "example.txt",
		LocalCACert: true,
	})
	joined := joinCommands(commands)
	for _, want := range []string{"-k", "--no-check-certificate", "-SkipCertificateCheck", "ServerCertificateValidationCallback", "verify=False", "_create_unverified_context"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("local CA commands do not contain %q:\n%s", want, joined)
		}
	}
}

func certificateTestConfig(keyType string) CertConfig {
	return CertConfig{
		Hosts:              []string{"files.example.test", "127.0.0.1"},
		ValidForDays:       2,
		KeyType:            keyType,
		ECDSACurve:         "P256",
		RSABits:            2048,
		CommonName:         "files.example.test",
		Organization:       "Example Server Organization",
		OrganizationalUnit: "Web Services",
		Country:            "US",
		Province:           "Server State",
		Locality:           "Server City",
	}
}

func certificateTestDirectory(t *testing.T) {
	t.Helper()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
}

func readGeneratedCertificates(t *testing.T) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile("cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		block, remaining := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatal("cert.pem contains invalid certificate PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse generated certificate: %v", err)
		}
		certificates = append(certificates, certificate)
		data = remaining
	}
	return certificates
}

func assertCertificateName(t *testing.T, got, want pkix.Name) {
	t.Helper()
	got.Names, got.ExtraNames = nil, nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("certificate name = %+v, want %+v", got, want)
	}
}
