package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPayloadManagerOneShotRotatesAndExpiresOldPath(t *testing.T) {
	manager := newPayloadManager("payload.bin", 1, pathFactory(t, "/first", "/second", "/third"))

	if got := manager.CurrentPath(); got != "/first" {
		t.Fatalf("CurrentPath() = %q, want /first", got)
	}

	match, ok := manager.Match("/first")
	if !ok {
		t.Fatal("Match(/first) = false, want true")
	}
	if match.FilePath != "payload.bin" {
		t.Fatalf("match.FilePath = %q, want payload.bin", match.FilePath)
	}
	if match.ExpiredPath != "/first" {
		t.Fatalf("match.ExpiredPath = %q, want /first", match.ExpiredPath)
	}
	if match.NewPath != "/second" {
		t.Fatalf("match.NewPath = %q, want /second", match.NewPath)
	}

	if _, ok := manager.Match("/first"); ok {
		t.Fatal("old path still matched after expiration")
	}
	if _, ok := manager.Match("/second"); !ok {
		t.Fatal("new path did not match after rotation")
	}
}

func TestPayloadManagerHonorsMaxDownloads(t *testing.T) {
	manager := newPayloadManager("payload.bin", 2, pathFactory(t, "/first", "/second"))

	firstMatch, ok := manager.Match("/first")
	if !ok {
		t.Fatal("first Match(/first) = false, want true")
	}
	if firstMatch.ExpiredPath != "" || firstMatch.NewPath != "" {
		t.Fatalf("first match rotated early: %+v", firstMatch)
	}
	if got := manager.CurrentPath(); got != "/first" {
		t.Fatalf("CurrentPath() after first match = %q, want /first", got)
	}

	secondMatch, ok := manager.Match("/first")
	if !ok {
		t.Fatal("second Match(/first) = false, want true")
	}
	if secondMatch.ExpiredPath != "/first" {
		t.Fatalf("second match ExpiredPath = %q, want /first", secondMatch.ExpiredPath)
	}
	if secondMatch.NewPath != "/second" {
		t.Fatalf("second match NewPath = %q, want /second", secondMatch.NewPath)
	}
}

func TestPayloadManagerPersistentPath(t *testing.T) {
	manager := newPayloadManager("payload.bin", 0, pathFactory(t, "/first"))

	for i := 0; i < 3; i++ {
		match, ok := manager.Match("/first")
		if !ok {
			t.Fatalf("Match(/first) at iteration %d = false, want true", i)
		}
		if match.ExpiredPath != "" || match.NewPath != "" {
			t.Fatalf("persistent path rotated at iteration %d: %+v", i, match)
		}
	}

	if got := manager.CurrentPath(); got != "/first" {
		t.Fatalf("CurrentPath() = %q, want /first", got)
	}
}

func TestPayloadManagerSwapDisableAndRotate(t *testing.T) {
	manager := newPayloadManager("", 1, pathFactory(t, "/first", "/second", "/third"))
	if manager.Active() {
		t.Fatal("empty payload manager should be inactive")
	}
	if _, ok := manager.Match("/first"); ok {
		t.Fatal("inactive payload manager matched a path")
	}

	manager.SwapFile("payload-one.bin", true)
	if got := manager.CurrentPath(); got != "/first" {
		t.Fatalf("CurrentPath() after swap = %q, want /first", got)
	}
	if manager.FilePath() != "payload-one.bin" {
		t.Fatalf("FilePath() = %q, want payload-one.bin", manager.FilePath())
	}

	manager.SwapFile("payload-two.bin", false)
	if got := manager.CurrentPath(); got != "/first" {
		t.Fatalf("CurrentPath() after non-rotating swap = %q, want /first", got)
	}
	if manager.RotatePath() != "/second" {
		t.Fatal("RotatePath() did not return the next generated path")
	}

	manager.Disable()
	if manager.Active() {
		t.Fatal("payload manager should be inactive after Disable()")
	}
	if got := manager.CurrentPath(); got != "" {
		t.Fatalf("CurrentPath() after Disable() = %q, want empty path", got)
	}
}

func TestPayloadRuntimeSwapUpdatesOutputNameAndRotatesURL(t *testing.T) {
	payloadPath := writeTempFile(t, "payload.bin", "hello")
	manager := newPayloadManager("", 1, pathFactory(t, "/first"))
	runtime := &PayloadRuntime{
		Manager: manager,
		Options: DownloadCommandOptions{
			MaxDownloads:   1,
			SelfSignedCert: true,
		},
	}

	if err := runtime.Swap(payloadPath, "", true); err != nil {
		t.Fatalf("Swap() error = %v", err)
	}
	if !runtime.Active() {
		t.Fatal("payload runtime should be active after Swap()")
	}

	options := runtime.CurrentCommandOptions("https://localhost:8443")
	if options.URL != "https://localhost:8443/first" {
		t.Fatalf("URL = %q, want https://localhost:8443/first", options.URL)
	}
	if options.OutputFile != "payload.bin" {
		t.Fatalf("OutputFile = %q, want payload.bin", options.OutputFile)
	}

	runtime.Disable()
	if runtime.Active() {
		t.Fatal("payload runtime should be inactive after Disable()")
	}
}

func pathFactory(t *testing.T, paths ...string) func() string {
	t.Helper()

	next := 0
	return func() string {
		if next >= len(paths) {
			t.Fatalf("path factory exhausted after %d path(s)", len(paths))
		}
		path := paths[next]
		next++
		return path
	}
}

func TestFormatAccessLogEntryText(t *testing.T) {
	entry := AccessLogEntry{
		Timestamp: "2026-06-30T12:00:00Z",
		ClientIP:  "127.0.0.1",
		UserAgent: "curl/8.0.0",
		Method:    "GET",
		Path:      "/download/file",
		Status:    200,
		LatencyMS: 1.25,
	}

	line, err := formatAccessLogEntry(entry, false)
	if err != nil {
		t.Fatalf("formatAccessLogEntry() error = %v", err)
	}

	for _, want := range []string{
		"2026-06-30T12:00:00Z",
		"IP: 127.0.0.1",
		"Method: GET",
		"Path: /download/file",
		"Status: 200",
		"Latency: 1.250ms",
		"User-Agent: curl/8.0.0",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("text access log %q does not contain %q", line, want)
		}
	}
}

func TestFormatAccessLogEntryJSON(t *testing.T) {
	entry := AccessLogEntry{
		Timestamp: "2026-06-30T12:00:00Z",
		ClientIP:  "127.0.0.1",
		UserAgent: "curl/8.0.0",
		Method:    "GET",
		Path:      "/download/file",
		Status:    200,
		LatencyMS: 1.25,
	}

	line, err := formatAccessLogEntry(entry, true)
	if err != nil {
		t.Fatalf("formatAccessLogEntry() error = %v", err)
	}

	var got AccessLogEntry
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("JSON access log did not unmarshal: %v", err)
	}
	if got != entry {
		t.Fatalf("JSON access log = %+v, want %+v", got, entry)
	}
}

func TestSetupRuntimeLogsNoAccessLogSkipsAccessFile(t *testing.T) {
	logDir := t.TempDir()

	runtimeLogs, err := setupRuntimeLogs(logDir, true, false)
	if err != nil {
		t.Fatalf("setupRuntimeLogs() error = %v", err)
	}
	defer runtimeLogs.Close()

	if runtimeLogs.accessMiddleware != nil {
		t.Fatal("access middleware was configured with noAccessLog=true")
	}
	if _, err := os.Stat(filepath.Join(logDir, "gin.log")); err != nil {
		t.Fatalf("gin.log was not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(logDir, "access.log")); !os.IsNotExist(err) {
		t.Fatalf("access.log exists with noAccessLog=true, stat error = %v", err)
	}
}

func TestSetupRuntimeLogsNoAccessLogStillSupportsObservers(t *testing.T) {
	logDir := t.TempDir()
	var observed []AccessLogEntry
	runtimeLogs, err := setupRuntimeLogsWithOptions(logDir, true, false, false, func(entry AccessLogEntry) {
		observed = append(observed, entry)
	})
	if err != nil {
		t.Fatalf("setupRuntimeLogsWithOptions() error = %v", err)
	}
	defer runtimeLogs.Close()

	if runtimeLogs.accessMiddleware == nil {
		t.Fatal("access middleware was not configured for dashboard observer")
	}
	if _, err := os.Stat(filepath.Join(logDir, "access.log")); !os.IsNotExist(err) {
		t.Fatalf("access.log exists with noAccessLog=true, stat error = %v", err)
	}

	logger := &AccessLogger{
		observers: []AccessLogObserver{func(entry AccessLogEntry) {
			observed = append(observed, entry)
		}},
	}
	if err := logger.Write(AccessLogEntry{Status: http.StatusOK, Method: http.MethodGet, Path: "/"}); err != nil {
		t.Fatalf("logger.Write() error = %v", err)
	}
	if len(observed) != 1 {
		t.Fatalf("observed entries = %d, want 1", len(observed))
	}
}

func TestAccessEventBufferTracksCountsAndRecentRequests(t *testing.T) {
	buffer := newAccessEventBuffer(2)
	buffer.Observe(AccessLogEntry{Timestamp: "2026-07-02T12:00:00Z", Method: http.MethodGet, Path: "/", Status: http.StatusOK})
	buffer.Observe(AccessLogEntry{Timestamp: "2026-07-02T12:00:01Z", Method: http.MethodGet, Path: "/missing", Status: http.StatusNotFound})
	buffer.Observe(AccessLogEntry{Timestamp: "2026-07-02T12:00:02Z", Method: http.MethodGet, Path: "/error", Status: http.StatusInternalServerError})

	snapshot := buffer.Snapshot()
	if snapshot.Total != 3 || snapshot.Success != 1 || snapshot.NotFound != 1 || snapshot.ServerErrors != 1 {
		t.Fatalf("snapshot counts = %+v, want total=3 success=1 notFound=1 serverErrors=1", snapshot)
	}
	if len(snapshot.Recent) != 2 {
		t.Fatalf("recent length = %d, want 2", len(snapshot.Recent))
	}
	if snapshot.Recent[0].Path != "/error" || snapshot.Recent[1].Path != "/missing" {
		t.Fatalf("recent entries = %+v, want newest two entries", snapshot.Recent)
	}
}

func TestRequestFilters(t *testing.T) {
	entries := []AccessLogEntry{
		{Status: http.StatusOK},
		{Status: http.StatusFound},
		{Status: http.StatusNotFound},
		{Status: http.StatusInternalServerError},
		{Status: http.StatusOK, Errors: "handler error"},
	}

	if got := len(filterRecentRequests(entries, requestFilterSuccess)); got != 3 {
		t.Fatalf("success filter count = %d, want 3", got)
	}
	if got := len(filterRecentRequests(entries, requestFilterNotFound)); got != 1 {
		t.Fatalf("404 filter count = %d, want 1", got)
	}
	if got := len(filterRecentRequests(entries, requestFilterErrors)); got != 2 {
		t.Fatalf("errors filter count = %d, want 2", got)
	}
	if nextRequestFilter(requestFilterErrors) != requestFilterAll {
		t.Fatal("request filter cycle should wrap back to all")
	}
}

func TestLoadHeaderConfigUsesDefaultProfile(t *testing.T) {
	path := writeTempFile(t, "headers.json", `{
		"default_profile": "dev-self-signed",
		"profiles": {
			"dev-self-signed": {
				"Cache-Control": "no-store",
				"X-Content-Type-Options": "nosniff"
			},
			"strict-security": {
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"X-Content-Type-Options": "nosniff"
			}
		}
	}`)

	headers, profile, err := loadHeaderConfig(path, "")
	if err != nil {
		t.Fatalf("loadHeaderConfig() error = %v", err)
	}
	if profile != "dev-self-signed" {
		t.Fatalf("profile = %q, want dev-self-signed", profile)
	}
	if headers["Cache-Control"] != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", headers["Cache-Control"])
	}
	if _, ok := headers["Strict-Transport-Security"]; ok {
		t.Fatal("dev-self-signed profile should not set Strict-Transport-Security")
	}
}

func TestLoadHeaderConfigSelectsRequestedProfile(t *testing.T) {
	path := writeTempFile(t, "headers.json", `{
		"default_profile": "dev-self-signed",
		"profiles": {
			"dev-self-signed": {
				"X-Content-Type-Options": "nosniff"
			},
			"strict-security": {
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains"
			}
		}
	}`)

	headers, profile, err := loadHeaderConfig(path, "strict-security")
	if err != nil {
		t.Fatalf("loadHeaderConfig() error = %v", err)
	}
	if profile != "strict-security" {
		t.Fatalf("profile = %q, want strict-security", profile)
	}
	if headers["Strict-Transport-Security"] == "" {
		t.Fatal("strict-security profile should set Strict-Transport-Security")
	}
}

func TestLoadHeaderConfigRejectsUnknownProfile(t *testing.T) {
	path := writeTempFile(t, "headers.json", `{
		"default_profile": "minimal-static",
		"profiles": {
			"minimal-static": {
				"X-Content-Type-Options": "nosniff"
			}
		}
	}`)

	if _, _, err := loadHeaderConfig(path, "missing-profile"); err == nil {
		t.Fatal("loadHeaderConfig() error = nil, want unknown profile error")
	}
}

func TestLoadHeaderConfigSupportsFlatMap(t *testing.T) {
	path := writeTempFile(t, "headers.json", `{
		"Cache-Control": "no-store",
		"X-Content-Type-Options": "nosniff"
	}`)

	headers, profile, err := loadHeaderConfig(path, "")
	if err != nil {
		t.Fatalf("loadHeaderConfig() error = %v", err)
	}
	if profile != "" {
		t.Fatalf("profile = %q, want empty profile for flat map", profile)
	}
	if headers["X-Content-Type-Options"] != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", headers["X-Content-Type-Options"])
	}
}

func TestLoadHeaderConfigRejectsProfileForFlatMap(t *testing.T) {
	path := writeTempFile(t, "headers.json", `{
		"Cache-Control": "no-store"
	}`)

	if _, _, err := loadHeaderConfig(path, "strict-security"); err == nil {
		t.Fatal("loadHeaderConfig() error = nil, want flat map profile error")
	}
}

func TestLoadCertConfigUsesDefaultProfile(t *testing.T) {
	path := writeTempFile(t, "cert_config.json", `{
		"default_profile": "local-dev",
		"profiles": {
			"local-dev": {
				"hosts": ["localhost", "127.0.0.1"],
				"valid_for_days": 365,
				"key_type": "ecdsa",
				"ecdsa_curve": "P256",
				"rsa_bits": 2048,
				"organization": "Local Development",
				"common_name": "localhost"
			},
			"public-site": {
				"hosts": ["www.example.test"],
				"valid_for_days": 90,
				"key_type": "ecdsa",
				"ecdsa_curve": "P256",
				"rsa_bits": 2048,
				"organization": "Example Website",
				"common_name": "www.example.test"
			}
		}
	}`)

	config, profile, err := loadCertConfig(path, "")
	if err != nil {
		t.Fatalf("loadCertConfig() error = %v", err)
	}
	if profile != "local-dev" {
		t.Fatalf("profile = %q, want local-dev", profile)
	}
	if config.CommonName != "localhost" {
		t.Fatalf("CommonName = %q, want localhost", config.CommonName)
	}
	if len(config.Hosts) != 2 || config.Hosts[0] != "localhost" {
		t.Fatalf("Hosts = %+v, want localhost first", config.Hosts)
	}
}

func TestLoadCertConfigSelectsRequestedProfile(t *testing.T) {
	path := writeTempFile(t, "cert_config.json", `{
		"default_profile": "local-dev",
		"profiles": {
			"local-dev": {
				"hosts": ["localhost"],
				"valid_for_days": 365,
				"key_type": "ecdsa",
				"ecdsa_curve": "P256",
				"rsa_bits": 2048,
				"common_name": "localhost"
			},
			"api-service": {
				"hosts": ["api.example.test"],
				"valid_for_days": 90,
				"key_type": "ecdsa",
				"ecdsa_curve": "P384",
				"rsa_bits": 2048,
				"common_name": "api.example.test"
			}
		}
	}`)

	config, profile, err := loadCertConfig(path, "api-service")
	if err != nil {
		t.Fatalf("loadCertConfig() error = %v", err)
	}
	if profile != "api-service" {
		t.Fatalf("profile = %q, want api-service", profile)
	}
	if config.ECDSACurve != "P384" {
		t.Fatalf("ECDSACurve = %q, want P384", config.ECDSACurve)
	}
}

func TestLoadCertConfigRejectsUnknownProfile(t *testing.T) {
	path := writeTempFile(t, "cert_config.json", `{
		"default_profile": "local-dev",
		"profiles": {
			"local-dev": {
				"hosts": ["localhost"],
				"valid_for_days": 365,
				"key_type": "ecdsa",
				"ecdsa_curve": "P256",
				"rsa_bits": 2048,
				"common_name": "localhost"
			}
		}
	}`)

	if _, _, err := loadCertConfig(path, "missing-profile"); err == nil {
		t.Fatal("loadCertConfig() error = nil, want unknown profile error")
	}
}

func TestLoadCertConfigSupportsFlatConfig(t *testing.T) {
	path := writeTempFile(t, "cert_config.json", `{
		"hosts": ["localhost"],
		"valid_for_days": 365,
		"key_type": "ecdsa",
		"ecdsa_curve": "P256",
		"rsa_bits": 2048,
		"common_name": "localhost"
	}`)

	config, profile, err := loadCertConfig(path, "")
	if err != nil {
		t.Fatalf("loadCertConfig() error = %v", err)
	}
	if profile != "" {
		t.Fatalf("profile = %q, want empty profile for flat config", profile)
	}
	if config.CommonName != "localhost" {
		t.Fatalf("CommonName = %q, want localhost", config.CommonName)
	}
}

func TestLoadCertConfigRejectsProfileForFlatConfig(t *testing.T) {
	path := writeTempFile(t, "cert_config.json", `{
		"hosts": ["localhost"],
		"valid_for_days": 365,
		"key_type": "ecdsa",
		"ecdsa_curve": "P256",
		"rsa_bits": 2048,
		"common_name": "localhost"
	}`)

	if _, _, err := loadCertConfig(path, "local-dev"); err == nil {
		t.Fatal("loadCertConfig() error = nil, want flat config profile error")
	}
}

func TestCheckedInProfileConfigsLoad(t *testing.T) {
	certConfig, certProfile, err := loadCertConfig("cert_config.json", "")
	if err != nil {
		t.Fatalf("loadCertConfig(cert_config.json) error = %v", err)
	}
	if certProfile != "local-dev" {
		t.Fatalf("default cert profile = %q, want local-dev", certProfile)
	}
	if certConfig.CommonName != "localhost" {
		t.Fatalf("default cert common name = %q, want localhost", certConfig.CommonName)
	}

	headers, headerProfile, err := loadHeaderConfig("headers.json", "")
	if err != nil {
		t.Fatalf("loadHeaderConfig(headers.json) error = %v", err)
	}
	if headerProfile != "dev-self-signed" {
		t.Fatalf("default header profile = %q, want dev-self-signed", headerProfile)
	}
	if _, ok := headers["Strict-Transport-Security"]; ok {
		t.Fatal("default header profile should not include Strict-Transport-Security")
	}
}

func TestCheckedInProfileConfigsExposeExpectedProfiles(t *testing.T) {
	for _, profile := range []string{"local-dev", "public-site", "api-service", "static-content", "internal-service"} {
		config, selectedProfile, err := loadCertConfig("cert_config.json", profile)
		if err != nil {
			t.Fatalf("loadCertConfig(%q) error = %v", profile, err)
		}
		if selectedProfile != profile {
			t.Fatalf("selected cert profile = %q, want %q", selectedProfile, profile)
		}
		if len(config.Hosts) == 0 {
			t.Fatalf("cert profile %q has no hosts", profile)
		}
		for fieldName, fieldValue := range map[string]string{
			"organization":        config.Organization,
			"organizational_unit": config.OrganizationalUnit,
			"country":             config.Country,
			"province":            config.Province,
			"locality":            config.Locality,
			"common_name":         config.CommonName,
		} {
			if strings.TrimSpace(fieldValue) == "" {
				t.Fatalf("cert profile %q has empty %s", profile, fieldName)
			}
		}
	}

	for _, profile := range []string{"minimal-static", "dev-self-signed", "general-website", "api-json", "strict-security"} {
		headers, selectedProfile, err := loadHeaderConfig("headers.json", profile)
		if err != nil {
			t.Fatalf("loadHeaderConfig(%q) error = %v", profile, err)
		}
		if selectedProfile != profile {
			t.Fatalf("selected header profile = %q, want %q", selectedProfile, profile)
		}
		if len(headers) == 0 {
			t.Fatalf("header profile %q has no headers", profile)
		}
	}
}

func TestPrepareStartupPlanIncludesDownloadAndProfileDetails(t *testing.T) {
	payloadPath := writeTempFile(t, "payload.bin", "hello")
	plan, err := prepareStartupPlan(AppConfig{
		SitePath:            "stage_options/IC-STAGE-1",
		PayloadFile:         payloadPath,
		PayloadMaxDownloads: 2,
		DownloadHost:        "127.0.0.1",
		DownloadPort:        8443,
		OutputName:          "",
		HTTPAddr:            ":8080",
		HTTPSAddr:           ":8443",
		CertConfigPath:      "cert_config.json",
		HeaderConfigPath:    "headers.json",
		LogDir:              ".",
	})
	if err != nil {
		t.Fatalf("prepareStartupPlan() error = %v", err)
	}

	if plan.CertProfile != "local-dev" {
		t.Fatalf("CertProfile = %q, want local-dev", plan.CertProfile)
	}
	if plan.HeaderProfile != "dev-self-signed" {
		t.Fatalf("HeaderProfile = %q, want dev-self-signed", plan.HeaderProfile)
	}
	if plan.DownloadBaseURL != "https://127.0.0.1:8443" {
		t.Fatalf("DownloadBaseURL = %q, want https://127.0.0.1:8443", plan.DownloadBaseURL)
	}
	if !strings.Contains(plan.PayloadURLShape, "<random>/<random>") {
		t.Fatalf("PayloadURLShape = %q, want randomized shape marker", plan.PayloadURLShape)
	}
	if plan.PayloadOutputFile != "payload.bin" {
		t.Fatalf("PayloadOutputFile = %q, want payload.bin", plan.PayloadOutputFile)
	}
}

func TestBuildDownloadBaseURLUsesConfiguredHostAndPort(t *testing.T) {
	got, err := buildDownloadBaseURL("files.example.test", 8443, nil)
	if err != nil {
		t.Fatalf("buildDownloadBaseURL() error = %v", err)
	}
	if got != "https://files.example.test:8443" {
		t.Fatalf("buildDownloadBaseURL() = %q, want https://files.example.test:8443", got)
	}
}

func TestBuildDownloadBaseURLDefaultsToCertHost(t *testing.T) {
	got, err := buildDownloadBaseURL("", 443, []string{"cert.example.test"})
	if err != nil {
		t.Fatalf("buildDownloadBaseURL() error = %v", err)
	}
	if got != "https://cert.example.test" {
		t.Fatalf("buildDownloadBaseURL() = %q, want https://cert.example.test", got)
	}
}

func TestBuildDownloadBaseURLFormatsIPv6Host(t *testing.T) {
	got, err := buildDownloadBaseURL("2001:db8::1", 443, nil)
	if err != nil {
		t.Fatalf("buildDownloadBaseURL() error = %v", err)
	}
	if got != "https://[2001:db8::1]" {
		t.Fatalf("buildDownloadBaseURL() = %q, want https://[2001:db8::1]", got)
	}
}

func TestPayloadOutputNameDefaultsToPayloadBasename(t *testing.T) {
	got := payloadOutputName(filepath.Join("payloads", "agent.bin"), "")
	if got != "agent.bin" {
		t.Fatalf("payloadOutputName() = %q, want agent.bin", got)
	}
}

func TestRenderDownloadCommandsSelfSignedIncludesCertificateBypass(t *testing.T) {
	commands := renderDownloadCommands(DownloadCommandOptions{
		URL:            "https://files.example.test:8443/a/b",
		OutputFile:     "agent.bin",
		SelfSignedCert: true,
	})
	joined := joinCommands(commands)

	for _, want := range []string{
		"-k",
		"--no-check-certificate",
		"-SkipCertificateCheck",
		"ServerCertificateValidationCallback",
		"verify=False",
		"_create_unverified_context",
		"agent.bin",
		"https://files.example.test:8443/a/b",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("self-signed commands do not contain %q:\n%s", want, joined)
		}
	}
}

func TestRenderDownloadCommandsTrustedOmitsCertificateBypass(t *testing.T) {
	commands := renderDownloadCommands(DownloadCommandOptions{
		URL:            "https://files.example.test/a/b",
		OutputFile:     "agent.bin",
		SelfSignedCert: false,
	})
	joined := joinCommands(commands)

	for _, unwanted := range []string{
		"-k",
		"--no-check-certificate",
		"-SkipCertificateCheck",
		"ServerCertificateValidationCallback",
		"verify=False",
		"_create_unverified_context",
	} {
		if strings.Contains(joined, unwanted) {
			t.Fatalf("trusted commands contain certificate bypass %q:\n%s", unwanted, joined)
		}
	}
}

func TestPortFromListenAddrParsesCommonForms(t *testing.T) {
	tests := map[string]int{
		":443":           443,
		"127.0.0.1:8443": 8443,
		"[::1]:9443":     9443,
	}

	for addr, want := range tests {
		got, err := portFromListenAddr(addr)
		if err != nil {
			t.Fatalf("portFromListenAddr(%q) error = %v", addr, err)
		}
		if got != want {
			t.Fatalf("portFromListenAddr(%q) = %d, want %d", addr, got, want)
		}
	}
}

func TestPortFromListenAddrRejectsMissingPort(t *testing.T) {
	if _, err := portFromListenAddr("127.0.0.1"); err == nil {
		t.Fatal("portFromListenAddr() error = nil, want missing port error")
	}
}

func TestListenerErrorSuggestionAddressInUse(t *testing.T) {
	err := formatListenerError("HTTPS", ":443", os.ErrExist)
	if !strings.Contains(err.Error(), "HTTPS listener could not bind to :443") {
		t.Fatalf("listener error missing context: %v", err)
	}

	err = formatListenerError("HTTPS", ":443", fakeError("bind: address already in use"))
	for _, want := range []string{"port for :443 appears to be in use", "--https-addr :8443"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("listener error %q does not contain %q", err.Error(), want)
		}
	}
}

func TestListenerErrorSuggestionPermissionDenied(t *testing.T) {
	err := formatListenerError("HTTP", ":80", fakeError("bind: permission denied"))
	for _, want := range []string{"may require elevated privileges", "--http-addr :8080"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("listener error %q does not contain %q", err.Error(), want)
		}
	}
}

func TestTLSCertificateErrorIsHelpful(t *testing.T) {
	err := formatTLSCertificateError("missing-cert.pem", "missing-key.pem", os.ErrNotExist)
	for _, want := range []string{"TLS certificate setup failed", "missing-cert.pem", "missing-key.pem", "certificate generation completed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("TLS error %q does not contain %q", err.Error(), want)
		}
	}
}

func TestValidateSitePathRejectsMissingIndex(t *testing.T) {
	sitePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(sitePath, "about.html"), []byte("<html></html>"), 0644); err != nil {
		t.Fatalf("write about.html: %v", err)
	}

	err := validateSitePath(sitePath)
	if err == nil {
		t.Fatal("validateSitePath() error = nil, want missing index error")
	}
	if !strings.Contains(err.Error(), "missing index.html") {
		t.Fatalf("validateSitePath() error = %q, want missing index.html", err.Error())
	}
}

func TestListStageSitePathsReturnsSortedDirectories(t *testing.T) {
	stageRoot := t.TempDir()
	for _, name := range []string{"IC-STAGE-3", "IC-STAGE-1", "IC-STAGE-2"} {
		if err := os.Mkdir(filepath.Join(stageRoot, name), 0755); err != nil {
			t.Fatalf("create stage dir: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(stageRoot, "README.txt"), []byte("not a stage"), 0644); err != nil {
		t.Fatalf("write non-directory entry: %v", err)
	}

	paths, err := listStageSitePaths(stageRoot)
	if err != nil {
		t.Fatalf("listStageSitePaths() error = %v", err)
	}

	want := []string{
		filepath.ToSlash(filepath.Join(stageRoot, "IC-STAGE-1")),
		filepath.ToSlash(filepath.Join(stageRoot, "IC-STAGE-2")),
		filepath.ToSlash(filepath.Join(stageRoot, "IC-STAGE-3")),
	}
	if len(paths) != len(want) {
		t.Fatalf("paths length = %d, want %d: %+v", len(paths), len(want), paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths[%d] = %q, want %q", i, paths[i], want[i])
		}
	}
}

func TestBuildSiteOptionsDefaultsToFirstStageForLegacyDefault(t *testing.T) {
	options, selectedIndex, selectedValue := buildSiteOptions([]string{
		"stage_options/IC-STAGE-1",
		"stage_options/IC-STAGE-2",
	}, defaultSitePath)

	if selectedValue != "stage_options/IC-STAGE-1" {
		t.Fatalf("selectedValue = %q, want first stage path", selectedValue)
	}
	if options[selectedIndex].Value != selectedValue {
		t.Fatalf("selected option value = %q, want %q", options[selectedIndex].Value, selectedValue)
	}
}

func TestBuildSiteOptionsPreservesCustomSitePath(t *testing.T) {
	options, selectedIndex, selectedValue := buildSiteOptions([]string{
		"stage_options/IC-STAGE-1",
		"stage_options/IC-STAGE-2",
	}, "custom/site")

	if selectedValue != "custom/site" {
		t.Fatalf("selectedValue = %q, want custom/site", selectedValue)
	}
	if selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want custom value at index 0", selectedIndex)
	}
	if options[0].Value != "custom/site" {
		t.Fatalf("custom option value = %q, want custom/site", options[0].Value)
	}
}

func TestListPayloadOptionFilesReturnsSortedFiles(t *testing.T) {
	payloadRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(payloadRoot, "zeta.bin"), []byte("z"), 0644); err != nil {
		t.Fatalf("write payload file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(payloadRoot, "nested"), 0755); err != nil {
		t.Fatalf("create nested dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(payloadRoot, "nested", "alpha.bin"), []byte("a"), 0644); err != nil {
		t.Fatalf("write nested payload file: %v", err)
	}

	paths, err := listPayloadOptionFiles(payloadRoot)
	if err != nil {
		t.Fatalf("listPayloadOptionFiles() error = %v", err)
	}

	want := []string{
		filepath.ToSlash(filepath.Join(payloadRoot, "nested", "alpha.bin")),
		filepath.ToSlash(filepath.Join(payloadRoot, "zeta.bin")),
	}
	if len(paths) != len(want) {
		t.Fatalf("paths length = %d, want %d: %+v", len(paths), len(want), paths)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths[%d] = %q, want %q", i, paths[i], want[i])
		}
	}
}

func TestBuildPayloadOptionsDefaultsToNone(t *testing.T) {
	options, selectedIndex, selectedValue := buildPayloadOptions([]string{
		"payload_options/agent.bin",
	}, "")

	if selectedValue != "" {
		t.Fatalf("selectedValue = %q, want empty payload", selectedValue)
	}
	if selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want none option", selectedIndex)
	}
	if options[0].Label != "(none)" || options[0].Value != "" {
		t.Fatalf("first option = %+v, want none option", options[0])
	}
}

func TestBuildPayloadOptionsPreservesCustomPayloadFile(t *testing.T) {
	options, selectedIndex, selectedValue := buildPayloadOptions([]string{
		"payload_options/agent.bin",
	}, "custom/payload.bin")

	if selectedValue != "custom/payload.bin" {
		t.Fatalf("selectedValue = %q, want custom/payload.bin", selectedValue)
	}
	if selectedIndex != 0 {
		t.Fatalf("selectedIndex = %d, want custom value at index 0", selectedIndex)
	}
	if options[0].Value != "custom/payload.bin" {
		t.Fatalf("custom option value = %q, want custom/payload.bin", options[0].Value)
	}
}

type fakeError string

func (e fakeError) Error() string {
	return string(e)
}

func joinCommands(commands []DownloadCommand) string {
	var builder strings.Builder
	for _, command := range commands {
		builder.WriteString(command.Label)
		builder.WriteString("\n")
		builder.WriteString(command.Command)
		builder.WriteString("\n")
	}
	return builder.String()
}

func writeTempFile(t *testing.T, name string, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
