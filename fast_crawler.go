package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"golang.org/x/net/html"
	"crypto/tls"
)

var (
	dnsResolvers = []string{
		"8.8.8.8:53",   // Google
		"1.1.1.1:53",   // Cloudflare
		"9.9.9.9:53",   // Quad9
		"208.67.222.222:53", // OpenDNS
		"76.76.2.0:53",      // Control D
		"94.140.14.14:53",   // AdGuard
		"185.228.168.9:53",  // Clean Browsing
		"77.88.8.8:53",      // Yandex
	}
	
	// Performance counters
	successCount   int64
	failCount      int64
	timeoutCount   int64
	dnsFailCount   int64
	processedCount int64
	startTime      time.Time
	
	// Detailed error counters
	tlsErrors      int64
	connRefused    int64
	connReset      int64
	noRoute        int64
	hostUnreach    int64
	netUnreach     int64
	addrNotAvail   int64
	
	// DNS cache
	dnsCache = sync.Map{}
	dnsExpiry = sync.Map{}
	
	// Statistics
	statusCodes   = sync.Map{}
	responseTime  = sync.Map{}
	errorTypes    = sync.Map{}

	// Common browser headers
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
	}

	acceptLanguages = []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.8",
		"en;q=0.7",
	}

	acceptHeaders = []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	}

	// Vulnerability counters
	dirListingFound    int64
	gitRepoFound       int64
	backupFilesFound   int64
	configFilesFound   int64
	apiDocsFound       int64
	debugEndpoints     int64
	adminPanelsFound   int64
	errorPagesFound    int64
)

// Common paths to check for vulnerabilities
var vulnerabilityPaths = []struct {
	path        string
	description string
	category    string
}{
	// Directory listings and information disclosure
	{"/robots.txt", "Robots.txt file", "info"},
	{"/.git/HEAD", "Exposed Git repository", "critical"},
	{"/.env", "Environment file", "critical"},
	{"/wp-config.php.bak", "WordPress backup config", "critical"},
	{"/config.php.bak", "PHP backup config", "critical"},
	{"/backup.sql", "Database backup", "critical"},
	{"/dump.sql", "Database dump", "critical"},
	
	// API and Debug endpoints
	{"/api/docs", "API Documentation", "info"},
	{"/swagger.json", "Swagger API spec", "info"},
	{"/swagger-ui.html", "Swagger UI", "info"},
	{"/debug", "Debug endpoint", "high"},
	{"/status", "Status endpoint", "medium"},
	{"/health", "Health check endpoint", "medium"},
	
	// Admin panels and CMS
	{"/wp-admin", "WordPress admin", "high"},
	{"/administrator", "Admin panel", "high"},
	{"/admin", "Admin panel", "high"},
	{"/phpmyadmin", "phpMyAdmin", "high"},
	{"/xmlrpc.php", "WordPress XML-RPC", "medium"},
	
	// Development and testing
	{"/dev", "Development endpoint", "medium"},
	{"/test", "Test endpoint", "medium"},
	{"/staging", "Staging environment", "medium"},
	{"/beta", "Beta environment", "medium"},
	
	// Common backup extensions
	{"/backup/", "Backup directory", "high"},
	{"/old/", "Old files directory", "medium"},
	{"/bak/", "Backup directory", "medium"},
	
	// Config and sensitive files
	{"/config/", "Configuration directory", "high"},
	{"/conf/", "Configuration directory", "high"},
	{"/cgi-bin/", "CGI scripts", "medium"},
	{"/.htaccess", "Apache config", "medium"},
	{"/web.config", "IIS config", "medium"},
}

// Patterns that might indicate vulnerabilities in responses
var vulnerabilityPatterns = []struct {
	pattern     string
	description string
	severity    string
}{
	{"Index of /", "Directory listing", "medium"},
	{"Fatal error:", "PHP error disclosure", "medium"},
	{"Warning:", "PHP warning disclosure", "low"},
	{"Stack trace:", "Stack trace disclosure", "high"},
	{"Exception in thread", "Java exception disclosure", "high"},
	{"error_reporting(", "PHP error reporting", "medium"},
	{"mysql_connect(", "MySQL connection string", "critical"},
	{"DATABASE_URL", "Database connection string", "critical"},
	{"API_KEY", "API key disclosure", "critical"},
	{"private key", "Private key disclosure", "critical"},
	{"BEGIN RSA PRIVATE KEY", "RSA private key disclosure", "critical"},
	{"password=", "Password in URL/config", "critical"},
}

// Add after the existing vulnerability patterns
var wordpressPatterns = []struct {
	path        string
	component   string
	description string
}{
	{"/wp-content/themes/", "theme", "WordPress theme directory"},
	{"/wp-content/plugins/", "plugin", "WordPress plugin directory"},
	{"/wp-includes/", "core", "WordPress core files"},
	{"/wp-admin/", "admin", "WordPress admin panel"},
	{"/wp-json/", "api", "WordPress REST API"},
}

// Common WordPress themes and plugins to check
var commonComponents = []string{
	// Popular themes
	"twentytwentyfour", "twentytwentythree", "twentytwentytwo", "twentytwentyone", "twentytwenty",
	"astra", "oceanwp", "generatepress", "neve", "divi", "avada", "sydney", "elementor",
	"hello-elementor", "storefront", "colibri-wp", "kadence", "blocksy", "porto",
	
	// Popular plugins
	"woocommerce", "wordpress-seo", "elementor", "contact-form-7", "wordfence",
	"akismet", "jetpack", "google-analytics-for-wordpress", "wp-super-cache",
	"wpforms-lite", "duplicate-post", "tinymce-advanced", "classic-editor",
	"advanced-custom-fields", "all-in-one-wp-migration", "updraftplus",
	"wp-optimize", "wp-rocket", "yoast-seo", "redirection", "wp-mail-smtp",
}

// Fast DNS resolver with connection reuse and retries
type Resolver struct {
	dialer *net.Dialer
	server string
}

func NewResolver(server string) *Resolver {
	return &Resolver{
		dialer: &net.Dialer{
			Timeout: 500 * time.Millisecond,  // Reduced from 1s to 500ms
		},
		server: server,
	}
}

func (r *Resolver) Resolve(domain string) ([]string, error) {
	// Check cache first with TTL
	if ips, ok := dnsCache.Load(domain); ok {
		if ttl, ok := dnsExpiry.Load(domain); ok {
			if ttl.(time.Time).After(time.Now()) {
				return ips.([]string), nil
			}
		}
	}

	// Try multiple DNS resolvers in parallel
	results := make(chan []string, len(dnsResolvers))
	errors := make(chan error, len(dnsResolvers))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for _, server := range dnsResolvers {
		go func(dns string) {
			resolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: 1 * time.Second,
					}
					return d.DialContext(ctx, "udp", dns)
				},
			}
			
			ips, err := resolver.LookupHost(ctx, domain)
			if err != nil {
				errors <- err
				return
			}
			results <- ips
		}(server)
	}

	// Wait for first successful result or all errors
	select {
	case ips := <-results:
		dnsCache.Store(domain, ips)
		dnsExpiry.Store(domain, time.Now().Add(5*time.Minute))
		return ips, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("dns_timeout")
	case err := <-errors:
		return nil, err
	}
}

// Fast HTTP client with optimized settings
func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        200,          // Increased from 100
			MaxIdleConnsPerHost: 20,           // Increased from 10
			MaxConnsPerHost:     20,           // Increased from 10
			IdleConnTimeout:     20 * time.Second,
			TLSHandshakeTimeout: 2 * time.Second,  // Reduced from 3s
			DisableCompression:  true,             // Added to reduce CPU usage
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
		},
		Timeout: 5 * time.Second,  // Reduced from 10s
	}
}

func addBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	req.Header.Set("Accept", acceptHeaders[rand.Intn(len(acceptHeaders))])
	req.Header.Set("Accept-Language", acceptLanguages[rand.Intn(len(acceptLanguages))])
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
}

func classifyError(err error) string {
	errStr := err.Error()
	
	switch {
	case strings.Contains(errStr, "tls:"):
		atomic.AddInt64(&tlsErrors, 1)
		return "tls_error"
	case strings.Contains(errStr, "connection refused"):
		atomic.AddInt64(&connRefused, 1)
		return "conn_refused"
	case strings.Contains(errStr, "connection reset"):
		atomic.AddInt64(&connReset, 1)
		return "conn_reset"
	case strings.Contains(errStr, "no route to host"):
		atomic.AddInt64(&noRoute, 1)
		return "no_route"
	case strings.Contains(errStr, "host is unreachable"):
		atomic.AddInt64(&hostUnreach, 1)
		return "host_unreachable"
	case strings.Contains(errStr, "network is unreachable"):
		atomic.AddInt64(&netUnreach, 1)
		return "net_unreachable"
	case strings.Contains(errStr, "cannot assign requested address"):
		atomic.AddInt64(&addrNotAvail, 1)
		return "addr_not_avail"
	case strings.Contains(errStr, "timeout"):
		return "timeout"
	default:
		return "other"
	}
}

// Add new types for structured output
type VulnType string

const (
	VulnTypeFileExposure   VulnType = "file_exposure"
	VulnTypeXSS            VulnType = "xss"
	VulnTypeSQLi           VulnType = "sql_injection"
	VulnTypeOpenRedirect   VulnType = "open_redirect"
	VulnTypeClickjacking   VulnType = "clickjacking"
	VulnTypeInfoDisclosure VulnType = "info_disclosure"
	VulnTypeMixedContent    VulnType = "mixed_content"
	VulnTypeWeakTLS         VulnType = "weak_tls"
	VulnTypeWeakCSP         VulnType = "weak_csp"
	VulnTypeWeakCookie      VulnType = "weak_cookie"
	VulnTypeTechDisclosure  VulnType = "tech_disclosure"
	VulnTypeWPPlugin        VulnType = "wordpress_plugin"
	VulnTypeWPTheme         VulnType = "wordpress_theme"
	VulnTypeWPCore          VulnType = "wordpress_core"
)

// Add test payloads
var (
	xssPayloads = []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg/onload=alert('XSS')>",
	}

	sqliPayloads = []string{
		"' OR '1'='1",
		"1' ORDER BY 1--",
		"1' UNION SELECT NULL--",
	}

	redirectPayloads = []string{
		"https://evil.com",
		"//evil.com",
		"/\\evil.com",
	}

	// Add error patterns
	sqlErrorPatterns = []string{
		"sql syntax",
		"mysql error",
		"postgresql error",
		"sqlite error",
		"database error",
	}
)

// Modify the Finding struct to include more details
type Finding struct {
	Timestamp   string            `json:"timestamp"`
	Domain      string            `json:"domain"`
	URL         string            `json:"url"`
	Type        VulnType          `json:"type"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	StatusCode  int              `json:"status_code"`
	Form        *FormDetails      `json:"form,omitempty"`
}

// Add form scanning capabilities
type FormDetails struct {
	Action  string            `json:"action"`
	Method  string            `json:"method"`
	Inputs  []FormInput       `json:"inputs"`
}

type FormInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
}

// Add new types for WordPress tracking
type WordPressInfo struct {
	IsWordPress      bool              `json:"is_wordpress"`
	Version          string            `json:"version,omitempty"`
	DetectedPlugins  map[string]string `json:"detected_plugins,omitempty"`  // plugin -> version
	VulnerablePlugins []VulnerablePlugin `json:"vulnerable_plugins,omitempty"`
	ExposedEndpoints []string          `json:"exposed_endpoints,omitempty"`
}

type VulnerablePlugin struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Path        string `json:"path"`
	CVE         string `json:"cve,omitempty"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// Update ScanResult to include WordPress info
type ScanResult struct {
	Domain          string    `json:"domain"`
	ScanTime        time.Time `json:"scan_time"`
	Findings        []Finding `json:"findings"`
	ResponseTime    string    `json:"response_time"`
	TotalRequests   int       `json:"total_requests"`
	SuccessfulReqs  int       `json:"successful_requests"`
	SecurityHeaders SecurityHeaderAnalysis `json:"security_headers"`
	TLSInfo         TLSAnalysis `json:"tls_info,omitempty"`
	WordPress       *WordPressInfo `json:"wordpress,omitempty"`
}

// Global variables for results
var (
	scanResults = struct {
		sync.Mutex
		Results map[string]*ScanResult
	}{
		Results: make(map[string]*ScanResult),
	}
)

// Add new security checks
var securityHeaders = []struct {
	header      string
	description string
	severity    string
}{
	{"Strict-Transport-Security", "Missing HSTS header", "medium"},
	{"Content-Security-Policy", "Missing CSP header", "high"},
	{"X-Frame-Options", "Missing X-Frame-Options header", "medium"},
	{"X-Content-Type-Options", "Missing X-Content-Type-Options header", "medium"},
	{"X-XSS-Protection", "Missing X-XSS-Protection header", "medium"},
	{"Referrer-Policy", "Missing Referrer-Policy header", "low"},
	{"Permissions-Policy", "Missing Permissions-Policy header", "low"},
}

var technologyPatterns = []struct {
	pattern     string
	description string
	severity    string
}{
	{"wp-content", "WordPress CMS detected", "info"},
	{"drupal", "Drupal CMS detected", "info"},
	{"joomla", "Joomla CMS detected", "info"},
	{"magento", "Magento platform detected", "info"},
	{"laravel", "Laravel framework detected", "info"},
	{"django", "Django framework detected", "info"},
	{"jquery", "jQuery library detected", "info"},
	{"bootstrap", "Bootstrap framework detected", "info"},
	{"react", "React framework detected", "info"},
	{"angular", "Angular framework detected", "info"},
}

var sensitiveEndpoints = []struct {
	path        string
	description string
	category    string
}{
	{"/server-status", "Apache Server Status exposed", "high"},
	{"/nginx_status", "Nginx Status exposed", "high"},
	{"/actuator", "Spring Boot Actuator exposed", "critical"},
	{"/metrics", "Application metrics exposed", "high"},
	{"/console", "Web console exposed", "critical"},
	{"/phpinfo.php", "PHP info page exposed", "high"},
	{"/api/v1/", "API endpoint exposed", "medium"},
	{".svn/entries", "SVN repository exposed", "critical"},
	{".hg/", "Mercurial repository exposed", "critical"},
	{"/.DS_Store", "DS_Store file exposed", "medium"},
}

// Add validation patterns
var (
	// Patterns that indicate a real backup directory
	backupDirPatterns = []string{
		"Index of /backup",
		"Index of /bak",
		"Directory listing for /backup",
		"Parent Directory",
	}

	// Patterns that indicate a real config file
	configFilePatterns = []string{
		"<?php",
		"define(",
		"DB_NAME",
		"DB_USER",
		"DB_PASSWORD",
		"DB_HOST",
		"SECURE_AUTH_KEY",
	}

	// Patterns that indicate a real .env file
	envFilePatterns = []string{
		"APP_NAME=",
		"APP_ENV=",
		"DB_CONNECTION=",
		"REDIS_HOST=",
		"MAIL_DRIVER=",
		"AWS_ACCESS_KEY",
	}

	// Patterns that indicate a real Git repository
	gitRepoPatterns = []string{
		"ref: refs/",
		"[core]",
		"repositoryformatversion",
	}

	// Patterns that indicate a real phpinfo page
	phpinfoPatterns = []string{
		"<title>PHP",
		"PHP Version",
		"PHP Credits",
		"PHP Configuration",
	}

	// Patterns that indicate a real server-status page
	serverStatusPatterns = []string{
		"Apache Server Status",
		"Server uptime:",
		"CPU Usage:",
		"CPU load:",
	}
)

// Add after the existing constants
type SecurityHeaderAnalysis struct {
	HSTS struct {
		Present   bool   `json:"present"`
		MaxAge    int    `json:"max_age,omitempty"`
		SubDomains bool  `json:"include_subdomains"`
		Preload    bool  `json:"preload"`
	} `json:"hsts"`
	CSP struct {
		Present     bool     `json:"present"`
		Directives  map[string]string `json:"directives,omitempty"`
		UnsafeDirectives []string `json:"unsafe_directives,omitempty"`
	} `json:"csp"`
	Cookies struct {
		Secure    bool `json:"secure"`
		HttpOnly  bool `json:"http_only"`
		SameSite  string `json:"same_site,omitempty"`
	} `json:"cookies"`
	ServerInfo struct {
		ServerHeader  string `json:"server_header,omitempty"`
		PoweredBy    string `json:"powered_by,omitempty"`
		Technologies []string `json:"technologies,omitempty"`
	} `json:"server_info"`
}

// Add new vulnerability patterns
var (
	// Unsafe CSP directives
	unsafeCSPDirectives = []string{
		"unsafe-inline",
		"unsafe-eval",
		"*",
		"data:",
		"http:",
	}

	// Technology fingerprints
	techFingerprints = map[string][]string{
		"WordPress": {
			"wp-content",
			"wp-includes",
			"wp-json",
		},
		"Angular": {
			"ng-app",
			"ng-controller",
			"angular.js",
		},
		"React": {
			"react.js",
			"react-dom",
			"_reactRootContainer",
		},
		"jQuery": {
			"jquery.js",
			"jquery.min.js",
		},
		"Bootstrap": {
			"bootstrap.css",
			"bootstrap.js",
		},
		"PHP": {
			"PHPSESSID",
			"X-Powered-By: PHP",
		},
		"ASP.NET": {
			"ASP.NET",
			"__VIEWSTATE",
			".aspx",
		},
		"Java": {
			"JSP",
			"Servlet",
			"JSESSIONID",
		},
	}

	// Mixed content patterns
	mixedContentPatterns = []string{
		"http://[^\"']*\\.(?:png|jpg|jpeg|gif|ico|css|js)",
		"http://[^\"']*\\.(googleapis|gstatic)\\.com",
		"http://ajax.googleapis.com",
	}
)

func sameSiteToString(sameSite http.SameSite) string {
	switch sameSite {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Default"
	}
}

func analyzeSecurityHeaders(resp *http.Response, result *ScanResult) {
	// HSTS Analysis
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		result.SecurityHeaders.HSTS.Present = true
		// Parse max-age
		if strings.Contains(hsts, "max-age=") {
			maxAge := strings.Split(strings.Split(hsts, "max-age=")[1], ";")[0]
			if age, err := strconv.Atoi(maxAge); err == nil {
				result.SecurityHeaders.HSTS.MaxAge = age
			}
		}
		result.SecurityHeaders.HSTS.SubDomains = strings.Contains(hsts, "includeSubDomains")
		result.SecurityHeaders.HSTS.Preload = strings.Contains(hsts, "preload")
	}

	// CSP Analysis
	if csp := resp.Header.Get("Content-Security-Policy"); csp != "" {
		result.SecurityHeaders.CSP.Present = true
		result.SecurityHeaders.CSP.Directives = make(map[string]string)
		
		// Parse CSP directives
		directives := strings.Split(csp, ";")
		for _, directive := range directives {
			directive = strings.TrimSpace(directive)
			if parts := strings.SplitN(directive, " ", 2); len(parts) == 2 {
				result.SecurityHeaders.CSP.Directives[parts[0]] = parts[1]
				
				// Check for unsafe directives
				for _, unsafe := range unsafeCSPDirectives {
					if strings.Contains(parts[1], unsafe) {
						result.SecurityHeaders.CSP.UnsafeDirectives = append(
							result.SecurityHeaders.CSP.UnsafeDirectives,
							fmt.Sprintf("%s: %s", parts[0], unsafe),
						)
					}
				}
			}
		}
	}

	// Cookie Analysis
	for _, cookie := range resp.Cookies() {
		result.SecurityHeaders.Cookies.Secure = result.SecurityHeaders.Cookies.Secure || cookie.Secure
		result.SecurityHeaders.Cookies.HttpOnly = result.SecurityHeaders.Cookies.HttpOnly || cookie.HttpOnly
		if cookie.SameSite != http.SameSiteDefaultMode {
			result.SecurityHeaders.Cookies.SameSite = sameSiteToString(cookie.SameSite)
		}
	}

	// Server Information Analysis
	if server := resp.Header.Get("Server"); server != "" {
		result.SecurityHeaders.ServerInfo.ServerHeader = server
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		result.SecurityHeaders.ServerInfo.PoweredBy = powered
	}

	// Technology Detection
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		bodyStr := string(body)
		for tech, patterns := range techFingerprints {
			for _, pattern := range patterns {
				if strings.Contains(bodyStr, pattern) {
					result.SecurityHeaders.ServerInfo.Technologies = append(
						result.SecurityHeaders.ServerInfo.Technologies,
						tech,
					)
					break
				}
			}
		}
	}
}

func analyzeTLS(resp *http.Response, result *ScanResult) {
	if resp.TLS == nil {
		return
	}

	tlsInfo := TLSAnalysis{
		Version:     fmt.Sprintf("%d.%d", resp.TLS.Version>>8, resp.TLS.Version&0xff),
		CipherSuite: tls.CipherSuiteName(resp.TLS.CipherSuite),
	}

	// Certificate analysis
	if len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		tlsInfo.CertIssuer = cert.Issuer.CommonName
		tlsInfo.CertValidDays = int(time.Until(cert.NotAfter).Hours() / 24)
		
		// Determine security level
		switch {
		case resp.TLS.Version >= tls.VersionTLS13:
			tlsInfo.SecurityLevel = "High"
		case resp.TLS.Version >= tls.VersionTLS12:
			tlsInfo.SecurityLevel = "Medium"
		default:
			tlsInfo.SecurityLevel = "Low"
		}
	}

	result.TLSInfo = tlsInfo
}

func checkDomain(domain string, client *http.Client, resolvers []*Resolver, resultChan chan<- string) {
	start := time.Now()
	
	// Initialize scan result for this domain
	result := &ScanResult{
		Domain:    domain,
		ScanTime:  time.Now(),
		Findings:  []Finding{},
	}
	
	defer func() {
		duration := time.Since(start)
		responseTime.Store(domain, duration)
		atomic.AddInt64(&processedCount, 1)
		
		// Store the result in the global map
		scanResults.Lock()
		result.ResponseTime = duration.String()
		result.TotalRequests = 1
		result.SuccessfulReqs = int(atomic.LoadInt64(&successCount))
		scanResults.Results[domain] = result
		scanResults.Unlock()
	}()
	
	// Try DNS resolution with all resolvers in parallel with balanced timeout
	resolved := make(chan bool, 1)
	dnsWg := sync.WaitGroup{}
	
	for _, resolver := range resolvers {
		if resolver == nil {
			continue
		}
		dnsWg.Add(1)
		go func(r *Resolver) {
			defer dnsWg.Done()
			if _, err := r.Resolve(domain); err == nil {
				select {
				case resolved <- true:
				default:
				}
			} else {
				errType := "dns_" + strings.Split(err.Error(), ":")[0]
				if val, ok := errorTypes.Load(errType); ok {
					errorTypes.Store(errType, val.(int)+1)
				} else {
					errorTypes.Store(errType, 1)
				}
			}
		}(resolver)
	}

	// Wait for either success or all resolvers to fail
	go func() {
		dnsWg.Wait()
		select {
		case resolved <- false: // All resolvers failed
		default:
		}
	}()

	select {
	case success := <-resolved:
		if !success {
			atomic.AddInt64(&dnsFailCount, 1)
			atomic.AddInt64(&failCount, 1)
			return
		}
	case <-time.After(3 * time.Second):  // Balanced DNS timeout
		atomic.AddInt64(&dnsFailCount, 1)
		atomic.AddInt64(&failCount, 1)
		return
	}

	// Try HTTP request with exponential backoff
	var resp *http.Response
	var lastErr error
	backoff := 300 * time.Millisecond  // Balanced initial backoff

	for retries := 0; retries < 2; retries++ { // Reduced retries
		url := "https://" + domain
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			lastErr = err
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		addBrowserHeaders(req)
		
		// Add cookies and other browser-like headers
		req.Header.Set("Cookie", "")
		req.Header.Set("Cache-Control", "max-age=0")
		req.Header.Set("Sec-Ch-Ua", "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not:A-Brand\";v=\"99\"")
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"Linux\"")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Sec-Fetch-Dest", "document")

		resp, err = client.Do(req)
		if err == nil {
			break
		}
		lastErr = err
		
		if strings.Contains(err.Error(), "timeout") {
			atomic.AddInt64(&timeoutCount, 1)
		}

		// Classify error type
		errType := classifyError(err)
		if val, ok := errorTypes.Load(errType); ok {
			errorTypes.Store(errType, val.(int)+1)
		} else {
			errorTypes.Store(errType, 1)
		}

		if retries < 1 { // Don't sleep on last retry
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	if lastErr != nil {
		atomic.AddInt64(&failCount, 1)
		return
	}

	if resp == nil {
		atomic.AddInt64(&failCount, 1)
		return
	}
	defer resp.Body.Close()

	// Follow redirects if needed
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			req, err := http.NewRequest("GET", location, nil)
			if err == nil {
				addBrowserHeaders(req)
				resp, err = client.Do(req)
				if err != nil {
					atomic.AddInt64(&failCount, 1)
					return
				}
			}
		}
	}

	if val, ok := statusCodes.Load(resp.StatusCode); ok {
		statusCodes.Store(resp.StatusCode, val.(int)+1)
	} else {
		statusCodes.Store(resp.StatusCode, 1)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		atomic.AddInt64(&successCount, 1)
		
		// Check for vulnerabilities
		if findings := checkVulnerabilities(domain, client); len(findings) > 0 {
			result.Findings = append(result.Findings, findings...)
			for _, finding := range findings {
				resultChan <- finding.String()
			}
		}
		
		// Extract title as before
		buf := make([]byte, 8192)
		n, _ := io.ReadFull(resp.Body, buf)
		if n > 0 {
			if title := extractTitle(buf[:n]); title != "" {
				resultChan <- fmt.Sprintf("[%d] %s: %s", resp.StatusCode, domain, title)
			}
		}
	} else {
		atomic.AddInt64(&failCount, 1)
	}

	// Check security headers
	analyzeSecurityHeaders(resp, result)
	analyzeTLS(resp, result)
}

func extractTitle(body []byte) string {
	start := strings.Index(strings.ToLower(string(body)), "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(strings.ToLower(string(body[start:])), "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(string(body[start : start+end]))
}

func printStats(domains []string, elapsed time.Duration) {
	fmt.Printf("\nDetailed Performance Summary:\n")
	fmt.Printf("============================\n")
	fmt.Printf("Total time: %s\n", elapsed)
	fmt.Printf("Total domains: %d\n", len(domains))
	fmt.Printf("Requests per second: %.2f\n", float64(len(domains))/elapsed.Seconds())
	fmt.Printf("Successful responses: %d (%.1f%%)\n", successCount, float64(successCount)/float64(len(domains))*100)
	fmt.Printf("Failed responses: %d\n", failCount)
	fmt.Printf("DNS failures: %d\n", dnsFailCount)
	fmt.Printf("Timeouts: %d\n", timeoutCount)

	fmt.Printf("\nDetailed Error Breakdown:\n")
	fmt.Printf("=======================\n")
	fmt.Printf("TLS errors: %d\n", atomic.LoadInt64(&tlsErrors))
	fmt.Printf("Connection refused: %d\n", atomic.LoadInt64(&connRefused))
	fmt.Printf("Connection reset: %d\n", atomic.LoadInt64(&connReset))
	fmt.Printf("No route to host: %d\n", atomic.LoadInt64(&noRoute))
	fmt.Printf("Host unreachable: %d\n", atomic.LoadInt64(&hostUnreach))
	fmt.Printf("Network unreachable: %d\n", atomic.LoadInt64(&netUnreach))
	fmt.Printf("Address not available: %d\n", atomic.LoadInt64(&addrNotAvail))

	fmt.Printf("\nStatus Code Distribution:\n")
	fmt.Printf("=======================\n")
	var codes []int
	statusCodes.Range(func(key, value interface{}) bool {
		codes = append(codes, key.(int))
		return true
	})
	sort.Ints(codes)
	for _, code := range codes {
		count, _ := statusCodes.Load(code)
		fmt.Printf("  HTTP %d: %d (%.1f%%)\n", code, count, float64(count.(int))/float64(len(domains))*100)
	}

	fmt.Printf("\nError Type Distribution:\n")
	fmt.Printf("======================\n")
	var errors []string
	errorTypes.Range(func(key, value interface{}) bool {
		errors = append(errors, key.(string))
		return true
	})
	sort.Strings(errors)
	for _, errType := range errors {
		count, _ := errorTypes.Load(errType)
		fmt.Printf("  %s: %d\n", errType, count)
	}

	// Calculate response time statistics
	var times []time.Duration
	responseTime.Range(func(key, value interface{}) bool {
		times = append(times, value.(time.Duration))
		return true
	})
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	if len(times) > 0 {
		var total time.Duration
		for _, t := range times {
			total += t
		}
		avg := total / time.Duration(len(times))
		p95 := times[len(times)*95/100]
		p99 := times[len(times)*99/100]

		fmt.Printf("\nResponse Time Statistics:\n")
		fmt.Printf("========================\n")
		fmt.Printf("  Average: %s\n", avg)
		fmt.Printf("  95th percentile: %s\n", p95)
		fmt.Printf("  99th percentile: %s\n", p99)
		fmt.Printf("  Slowest: %s\n", times[len(times)-1])
		fmt.Printf("  Fastest: %s\n", times[0])
	}

	fmt.Printf("\nVulnerability Scan Results:\n")
	fmt.Printf("==========================\n")
	fmt.Printf("Directory Listings: %d\n", atomic.LoadInt64(&dirListingFound))
	fmt.Printf("Git Repositories: %d\n", atomic.LoadInt64(&gitRepoFound))
	fmt.Printf("Backup Files: %d\n", atomic.LoadInt64(&backupFilesFound))
	fmt.Printf("Config Files: %d\n", atomic.LoadInt64(&configFilesFound))
	fmt.Printf("API Docs: %d\n", atomic.LoadInt64(&apiDocsFound))
	fmt.Printf("Debug Endpoints: %d\n", atomic.LoadInt64(&debugEndpoints))
	fmt.Printf("Admin Panels: %d\n", atomic.LoadInt64(&adminPanelsFound))
	fmt.Printf("Error Pages with Sensitive Info: %d\n", atomic.LoadInt64(&errorPagesFound))

	fmt.Printf("\nWordPress Statistics:\n")
	fmt.Printf("===================\n")
	wpCount := 0
	vulnPluginCount := 0
	pluginMap := make(map[string]int)
	vulnPluginMap := make(map[string]int)

	scanResults.Lock()
	for _, result := range scanResults.Results {
		if result.WordPress != nil && result.WordPress.IsWordPress {
			wpCount++
			for plugin := range result.WordPress.DetectedPlugins {
				pluginMap[plugin]++
			}
			for _, vuln := range result.WordPress.VulnerablePlugins {
				vulnPluginCount++
				vulnPluginMap[vuln.Name]++
			}
		}
	}
	scanResults.Unlock()

	fmt.Printf("WordPress sites found: %d (%.1f%%)\n", wpCount, float64(wpCount)/float64(len(domains))*100)
	fmt.Printf("Sites with vulnerable plugins: %d\n", vulnPluginCount)
	
	fmt.Printf("\nTop WordPress Plugins:\n")
	for plugin, count := range pluginMap {
		fmt.Printf("  %s: %d sites\n", plugin, count)
	}

	fmt.Printf("\nVulnerable Plugins Found:\n")
	for plugin, count := range vulnPluginMap {
		fmt.Printf("  %s: %d sites\n", plugin, count)
	}
}

// Add to main() before it ends
func saveResults(filename string) error {
	scanResults.Lock()
	defer scanResults.Unlock()

	results := struct {
		Timestamp   string                `json:"timestamp"`
		TotalScans  int                   `json:"total_scans"`
		Results     map[string]*ScanResult `json:"results"`
	}{
		Timestamp:   time.Now().Format(time.RFC3339),
		TotalScans:  len(scanResults.Results),
		Results:     scanResults.Results,
	}

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func main() {
	concurrency := flag.Int("concurrency", 200, "Number of concurrent checkers")  // Increased from 100
	maxDomains := flag.Int("max", 100, "Maximum number of domains to process")
	csvFile := flag.String("file", "top-1m.csv", "CSV file with domains")
	resultsFile := flag.String("output", "vulnerability_scan_results.json", "Output JSON file for results")
	flag.Parse()

	startTime = time.Now()

	// Initialize resolvers with a smaller pool
	var resolvers []*Resolver
	for _, server := range dnsResolvers[:4] { // Use only first 4 resolvers for faster DNS
		resolvers = append(resolvers, NewResolver(server))
	}

	// Create HTTP client pool
	client := newHTTPClient()

	// Read domains
	file, err := os.Open(*csvFile)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	domains := make([]string, 0, *maxDomains)
	for i := 0; i < *maxDomains; i++ {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < 2 {
			continue
		}
		domains = append(domains, strings.TrimSpace(record[1]))
	}

	// Process domains with increased buffer sizes
	resultChan := make(chan string, *concurrency*2)
	doneChan := make(chan bool)
	
	// Start result printer with buffered processing
	go func() {
		buffer := make([]string, 0, 100)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case result, ok := <-resultChan:
				if !ok {
					// Flush remaining results
					if len(buffer) > 0 {
						for _, r := range buffer {
							fmt.Println(r)
						}
					}
					doneChan <- true
					return
				}
				buffer = append(buffer, result)
				if len(buffer) >= 100 {
					for _, r := range buffer {
						fmt.Println(r)
					}
					buffer = buffer[:0]
				}
			case <-ticker.C:
				if len(buffer) > 0 {
					for _, r := range buffer {
						fmt.Println(r)
					}
					buffer = buffer[:0]
				}
			}
		}
	}()

	// Start workers with work stealing
	workChan := make(chan string, *concurrency*2)
	var wg sync.WaitGroup
	
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range workChan {
				checkDomain(domain, client, resolvers, resultChan)
			}
		}()
	}

	// Feed domains to workers in batches
	batchSize := 50
	for i := 0; i < len(domains); i += batchSize {
		end := i + batchSize
		if end > len(domains) {
			end = len(domains)
		}
		batch := domains[i:end]
		for _, domain := range batch {
			workChan <- domain
		}
	}
	close(workChan)

	// Wait for completion
	wg.Wait()
	close(resultChan)
	<-doneChan

	elapsed := time.Since(startTime)
	printStats(domains, elapsed)

	// Save results to JSON file
	if err := saveResults(*resultsFile); err != nil {
		fmt.Printf("Error saving results to %s: %v\n", *resultsFile, err)
	} else {
		fmt.Printf("\nResults saved to: %s\n", *resultsFile)
	}
}

// Add back the String() method for Finding
func (f Finding) String() string {
	base := fmt.Sprintf("[VULN:%s] %s - %s", f.Severity, f.URL, f.Description)
	if f.Evidence != "" {
		base += fmt.Sprintf(" (Evidence: %s)", f.Evidence)
	}
	return base
}

// Add HTML node type constants
const (
	ElementNode html.NodeType = 1
)

// Update checkVulnerabilities to include WordPress info
func checkVulnerabilities(domain string, client *http.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := "https://" + domain
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return findings
	}

	addBrowserHeaders(req)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return findings
	}
	defer resp.Body.Close()

	respData, err := analyzeResponse(resp)
	if err != nil {
		return findings
	}

	// Run analyses in parallel
	wg.Add(5)

	// WordPress check with info gathering
	go func() {
		defer wg.Done()
		if wpFindings, wpInfo := checkWordPressVulnerabilities(domain, client); len(wpFindings) > 0 {
			mu.Lock()
			findings = append(findings, wpFindings...)
			// Store WordPress info in the global results
			if result, exists := scanResults.Results[domain]; exists && wpInfo != nil {
				result.WordPress = wpInfo
			}
			mu.Unlock()
		}
	}()

	// Check mixed content
	go func() {
		defer wg.Done()
		if mixedFindings := checkMixedContent(respData.bodyString); len(mixedFindings) > 0 {
			mu.Lock()
			findings = append(findings, mixedFindings...)
			mu.Unlock()
		}
	}()

	// Check TLS
	go func() {
		defer wg.Done()
		if respData.tlsInfo != nil {
			if tlsFindings := checkTLSIssues(respData.tlsInfo); len(tlsFindings) > 0 {
				mu.Lock()
				findings = append(findings, tlsFindings...)
				mu.Unlock()
			}
		}
	}()

	// Check security headers
	go func() {
		defer wg.Done()
		if headerFindings := checkSecurityHeaders(respData.headers, domain); len(headerFindings) > 0 {
			mu.Lock()
			findings = append(findings, headerFindings...)
			mu.Unlock()
		}
	}()

	// Check technology disclosure
	go func() {
		defer wg.Done()
		if techFindings := checkTechnologyDisclosure(respData.bodyString); len(techFindings) > 0 {
			mu.Lock()
			findings = append(findings, techFindings...)
			mu.Unlock()
		}
	}()

	wg.Wait()

	// Add common metadata to all findings
	for i := range findings {
		findings[i].Timestamp = time.Now().Format(time.RFC3339)
		findings[i].Domain = domain
		findings[i].URL = url
		findings[i].StatusCode = respData.statusCode
	}

	return findings
}

// Update checkWordPressVulnerabilities to track more plugin information
func checkWordPressVulnerabilities(domain string, client *http.Client) ([]Finding, *WordPressInfo) {
	var findings []Finding
	wpInfo := &WordPressInfo{
		DetectedPlugins: make(map[string]string),
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First check if it's a WordPress site
	wpAdminURL := "https://" + domain + "/wp-admin/"
	wpLoginURL := "https://" + domain + "/wp-login.php"
	wpContentURL := "https://" + domain + "/wp-content/"

	for _, url := range []string{wpAdminURL, wpLoginURL, wpContentURL} {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		addBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			wpInfo.IsWordPress = true
			break
		}
	}

	if !wpInfo.IsWordPress {
		return findings, nil
	}

	// Try to detect WordPress version
	generatorURL := "https://" + domain + "/feed/"
	if req, err := http.NewRequestWithContext(ctx, "GET", generatorURL, nil); err == nil {
		if resp, err := client.Do(req); err == nil && resp != nil {
			defer resp.Body.Close()
			if body, err := io.ReadAll(resp.Body); err == nil {
				if matches := regexp.MustCompile(`<generator>https://wordpress.org/\?v=([\d.]+)</generator>`).FindSubmatch(body); len(matches) > 1 {
					wpInfo.Version = string(matches[1])
				}
			}
		}
	}

	// Check for all common plugins first
	for _, plugin := range commonComponents {
		pluginURL := "https://" + domain + "/wp-content/plugins/" + plugin + "/"
		req, err := http.NewRequestWithContext(ctx, "GET", pluginURL, nil)
		if err != nil {
			continue
		}
		addBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			// Try to detect version
			versionURL := pluginURL + "readme.txt"
			version := detectPluginVersion(versionURL, client)
			wpInfo.DetectedPlugins[plugin] = version
		}
	}

	// Check specifically for known vulnerable plugins
	for _, vuln := range wordpressVulnerabilities {
		pluginURL := "https://" + domain + vuln.checkPath
		req, err := http.NewRequestWithContext(ctx, "GET", pluginURL, nil)
		if err != nil {
			continue
		}
		addBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			version := detectPluginVersion(pluginURL+"readme.txt", client)
			
			vulnPlugin := VulnerablePlugin{
				Name:        vuln.pluginSlug,
				Version:     version,
				Path:        vuln.checkPath,
				CVE:         vuln.cve,
				Description: vuln.description,
				Severity:    vuln.severity,
			}
			wpInfo.VulnerablePlugins = append(wpInfo.VulnerablePlugins, vulnPlugin)

			findings = append(findings, Finding{
				Type:        VulnTypeWPPlugin,
				Severity:    vuln.severity,
				Description: fmt.Sprintf("Potentially vulnerable WordPress plugin: %s %s (%s)", 
					vuln.pluginSlug, version, vuln.cve),
				Evidence:    fmt.Sprintf("Plugin directory found at %s, version: %s", vuln.checkPath, version),
			})
		}
	}

	// Check for common WordPress vulnerabilities and exposed endpoints
	commonVulnPaths := []struct {
		path        string
		description string
		severity    string
	}{
		{"/wp-json/wp/v2/users/", "WordPress User Enumeration via REST API", "medium"},
		{"/wp-content/uploads/", "Directory Listing Enabled", "medium"},
		{"/wp-content/debug.log", "Debug Log Exposure", "high"},
		{"/wp-config.php.bak", "WordPress Config Backup", "critical"},
		{"/wp-content/plugins/", "Plugin Directory Listing", "medium"},
		{"/wp-content/themes/", "Theme Directory Listing", "medium"},
	}

	for _, vuln := range commonVulnPaths {
		url := "https://" + domain + vuln.path
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		addBrowserHeaders(req)
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			wpInfo.ExposedEndpoints = append(wpInfo.ExposedEndpoints, vuln.path)
			findings = append(findings, Finding{
				Type:        VulnTypeWPCore,
				Severity:    vuln.severity,
				Description: vuln.description,
				Evidence:    fmt.Sprintf("Accessible at %s", vuln.path),
			})
		}
	}

	return findings, wpInfo
}

// Helper function to detect plugin version
func detectPluginVersion(versionURL string, client *http.Client) string {
	req, err := http.NewRequest("GET", versionURL, nil)
	if err != nil {
		return "unknown"
	}
	addBrowserHeaders(req)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return "unknown"
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unknown"
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "Stable tag:") {
		parts := strings.Split(bodyStr, "Stable tag:")
		if len(parts) > 1 {
			version := strings.TrimSpace(strings.Split(parts[1], "\n")[0])
			return version
		}
	}
	return "unknown"
}

func checkTLSIssues(tlsState *tls.ConnectionState) []Finding {
	var findings []Finding

	// Check TLS version
	if tlsState.Version < tls.VersionTLS12 {
		findings = append(findings, Finding{
			Type:        VulnTypeWeakTLS,
			Severity:    "high",
			Description: "Weak TLS version detected",
			Evidence:    fmt.Sprintf("TLS %d.%d", tlsState.Version>>8, tlsState.Version&0xff),
		})
	}

	// Check certificate expiration
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysUntilExpiry < 30 {
			findings = append(findings, Finding{
				Type:        VulnTypeWeakTLS,
				Severity:    "high",
				Description: "Certificate expiring soon",
				Evidence:    fmt.Sprintf("Expires in %d days", daysUntilExpiry),
			})
		}
	}

	return findings
}

func checkSecurityHeaders(headers http.Header, domain string) []Finding {
	var findings []Finding

	// Check CSP
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		for _, directive := range strings.Split(csp, ";") {
			directive = strings.TrimSpace(directive)
			for _, unsafe := range unsafeCSPDirectives {
				if strings.Contains(directive, unsafe) {
					findings = append(findings, Finding{
						Type:        VulnTypeWeakCSP,
						Severity:    "medium",
						Description: "Unsafe CSP directive found",
						Evidence:    fmt.Sprintf("Directive contains: %s", unsafe),
					})
					break
				}
			}
		}
	}

	// Check cookies
	for _, cookie := range headers["Set-Cookie"] {
		if !strings.Contains(cookie, "Secure") || !strings.Contains(cookie, "HttpOnly") {
			findings = append(findings, Finding{
				Type:        VulnTypeWeakCookie,
				Severity:    "medium",
				Description: "Insecure cookie settings",
				Evidence:    fmt.Sprintf("Cookie %s: Missing security flags", strings.Split(cookie, "=")[0]),
			})
		}
	}

	return findings
}

func checkTechnologyDisclosure(body string) []Finding {
	var findings []Finding

	for tech, patterns := range techFingerprints {
		for _, pattern := range patterns {
			if strings.Contains(body, pattern) {
				findings = append(findings, Finding{
					Type:        VulnTypeTechDisclosure,
					Severity:    "low",
					Description: "Technology stack disclosed",
					Evidence:    fmt.Sprintf("Detected: %s", tech),
				})
				break
			}
		}
	}

	return findings
}

func checkMixedContent(body string) []Finding {
	var findings []Finding
	
	for _, pattern := range mixedContentPatterns {
		if matches := regexp.MustCompile(pattern).FindAllString(body, -1); len(matches) > 0 {
			findings = append(findings, Finding{
				Type:        VulnTypeMixedContent,
				Severity:    "medium",
				Description: "Mixed content found: HTTP resources on HTTPS page",
				Evidence:    strings.Join(matches[:min(3, len(matches))], ", "),
			})
			break
		}
	}
	
	return findings
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Add after the existing types
type ResponseData struct {
	body        []byte
	bodyString  string
	headers     http.Header
	statusCode  int
	tlsInfo     *tls.ConnectionState
}

func analyzeResponse(resp *http.Response) (*ResponseData, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &ResponseData{
		body:       body,
		bodyString: string(body),
		headers:    resp.Header,
		statusCode: resp.StatusCode,
		tlsInfo:    resp.TLS,
	}, nil
}

// Add back TLSAnalysis struct
type TLSAnalysis struct {
	Version          string   `json:"version"`
	CipherSuite      string   `json:"cipher_suite"`
	CertValidDays    int      `json:"cert_valid_days"`
	CertIssuer       string   `json:"cert_issuer"`
	OCSPStapling     bool     `json:"ocsp_stapling"`
	SecurityLevel    string   `json:"security_level"` // High, Medium, Low based on configuration
}

// Add back WordPress vulnerability definitions
var wordpressVulnerabilities = []struct {
	pluginSlug   string
	version      string
	cve          string
	description  string
	severity     string
	checkPath    string
	fingerprint  string
}{
	{
		pluginSlug:   "user-registration",
		version:      "4.1.2",
		cve:          "CVE-2025-2594",
		description:  "User Registration & Membership Plugin Authentication Bypass",
		severity:     "critical",
		checkPath:    "/wp-content/plugins/user-registration/",
		fingerprint:  "user-registration/includes/class-ur-ajax.php",
	},
	{
		pluginSlug:   "wp-fastest-cache",
		version:      "1.2.2",
		cve:          "CVE-2024-1001",
		description:  "WP Fastest Cache - Unauthenticated RCE",
		severity:     "critical",
		checkPath:    "/wp-content/plugins/wp-fastest-cache/",
		fingerprint:  "wp-fastest-cache/inc/cache.php",
	},
	{
		pluginSlug:   "contact-form-7",
		version:      "5.8.2",
		cve:          "CVE-2023-3356",
		description:  "Contact Form 7 Cross-Site Scripting",
		severity:     "medium",
		checkPath:    "/wp-content/plugins/contact-form-7/",
		fingerprint:  "contact-form-7/wp-contact-form-7.php",
	},
} 