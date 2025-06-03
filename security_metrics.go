package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type SecurityMetrics struct {
	TotalSites          int     `json:"total_sites"`
	HSTSStats           HSTSMetrics `json:"hsts_stats"`
	CSPStats            CSPMetrics  `json:"csp_stats"`
	CookieStats         CookieMetrics `json:"cookie_stats"`
	WordPressStats      WordPressMetrics `json:"wordpress_stats"`
	TLSStats            TLSMetrics `json:"tls_stats"`
}

type HSTSMetrics struct {
	SitesWithHSTS       int     `json:"sites_with_hsts"`
	SitesWithoutHSTS    int     `json:"sites_without_hsts"`
	HSTSPercentage      float64 `json:"hsts_percentage"`
	PreloadEnabled      int     `json:"preload_enabled"`
	IncludeSubdomains   int     `json:"include_subdomains"`
}

type CSPMetrics struct {
	SitesWithCSP        int     `json:"sites_with_csp"`
	SitesWithoutCSP     int     `json:"sites_without_csp"`
	CSPPercentage       float64 `json:"csp_percentage"`
	UnsafeInline        int     `json:"unsafe_inline_count"`
	UnsafeEval          int     `json:"unsafe_eval_count"`
	WildcardSources     int     `json:"wildcard_sources"`
}

type CookieMetrics struct {
	TotalCookies        int     `json:"total_cookies"`
	InsecureCookies     int     `json:"insecure_cookies"`
	SecureCookies       int     `json:"secure_cookies"`
	HttpOnlyCookies     int     `json:"httponly_cookies"`
	SameSiteStrict      int     `json:"samesite_strict"`
	SameSiteLax         int     `json:"samesite_lax"`
	SameSiteNone        int     `json:"samesite_none"`
	AvgCookiesPerSite   float64 `json:"avg_cookies_per_site"`
}

type WordPressMetrics struct {
	WordPressSites      int     `json:"wordpress_sites"`
	VulnerablePlugins   int     `json:"vulnerable_plugins"`
	VulnerableThemes    int     `json:"vulnerable_themes"`
	OutdatedCore        int     `json:"outdated_core"`
	CVECount            int     `json:"cve_count"`
	HighSeverity        int     `json:"high_severity"`
	MediumSeverity      int     `json:"medium_severity"`
	LowSeverity         int     `json:"low_severity"`
}

type TLSMetrics struct {
	ModernTLS           int     `json:"modern_tls"`  // TLS 1.3
	IntermediateTLS     int     `json:"intermediate_tls"` // TLS 1.2
	OldTLS              int     `json:"old_tls"` // TLS 1.1 or lower
	WeakCiphers        int     `json:"weak_ciphers"`
	StrongCiphers      int     `json:"strong_ciphers"`
	ValidCerts         int     `json:"valid_certs"`
	ExpiredCerts       int     `json:"expired_certs"`
	SelfSignedCerts    int     `json:"self_signed_certs"`
}

func AnalyzeResults(resultsFile string) (*SecurityMetrics, error) {
	// Read the scan results file
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %v", err)
	}

	// Parse the JSON results - update to match the structure from saveResults()
	var resultsWrapper struct {
		Timestamp   string                `json:"timestamp"`
		TotalScans  int                   `json:"total_scans"`
		Results     map[string]*ScanResult `json:"results"`
	}
	
	if err := json.Unmarshal(data, &resultsWrapper); err != nil {
		return nil, fmt.Errorf("failed to parse results: %v", err)
	}

	metrics := &SecurityMetrics{}
	metrics.TotalSites = resultsWrapper.TotalScans

	// Initialize counters
	metrics.HSTSStats = HSTSMetrics{}
	metrics.CSPStats = CSPMetrics{}
	metrics.CookieStats = CookieMetrics{}
	metrics.WordPressStats = WordPressMetrics{}
	metrics.TLSStats = TLSMetrics{}

	// Analyze each site
	for _, result := range resultsWrapper.Results {
		// HSTS Analysis
		if result.SecurityHeaders.HSTS.Present {
			metrics.HSTSStats.SitesWithHSTS++
			if result.SecurityHeaders.HSTS.Preload {
				metrics.HSTSStats.PreloadEnabled++
			}
			if result.SecurityHeaders.HSTS.SubDomains {
				metrics.HSTSStats.IncludeSubdomains++
			}
		} else {
			metrics.HSTSStats.SitesWithoutHSTS++
		}

		// CSP Analysis
		if result.SecurityHeaders.CSP.Present {
			metrics.CSPStats.SitesWithCSP++
			if result.SecurityHeaders.CSP.Directives != nil {
				for _, directive := range result.SecurityHeaders.CSP.UnsafeDirectives {
					if directive == "script-src: unsafe-inline" {
						metrics.CSPStats.UnsafeInline++
					}
					if directive == "script-src: unsafe-eval" {
						metrics.CSPStats.UnsafeEval++
					}
					if directive == "script-src: *" {
						metrics.CSPStats.WildcardSources++
					}
				}
			}
		} else {
			metrics.CSPStats.SitesWithoutCSP++
		}

		// Cookie Analysis
		if result.SecurityHeaders.Cookies.Secure {
			metrics.CookieStats.SecureCookies++
		} else {
			metrics.CookieStats.InsecureCookies++
		}
		if result.SecurityHeaders.Cookies.HttpOnly {
			metrics.CookieStats.HttpOnlyCookies++
		}
		switch result.SecurityHeaders.Cookies.SameSite {
		case "Strict":
			metrics.CookieStats.SameSiteStrict++
		case "Lax":
			metrics.CookieStats.SameSiteLax++
		case "None":
			metrics.CookieStats.SameSiteNone++
		}

		// TLS Analysis
		if result.TLSInfo.Version == "3.4" {
			metrics.TLSStats.ModernTLS++
		} else if result.TLSInfo.Version == "3.3" {
			metrics.TLSStats.IntermediateTLS++
		} else {
			metrics.TLSStats.OldTLS++
		}

		// WordPress Analysis
		if result.WordPress != nil && result.WordPress.IsWordPress {
			metrics.WordPressStats.WordPressSites++
			metrics.WordPressStats.VulnerablePlugins += len(result.WordPress.VulnerablePlugins)
			
			for _, vuln := range result.WordPress.VulnerablePlugins {
				metrics.WordPressStats.CVECount++
				switch vuln.Severity {
				case "high":
					metrics.WordPressStats.HighSeverity++
				case "medium":
					metrics.WordPressStats.MediumSeverity++
				case "low":
					metrics.WordPressStats.LowSeverity++
				}
			}
		}
	}

	// Calculate percentages
	if metrics.TotalSites > 0 {
		metrics.HSTSStats.HSTSPercentage = float64(metrics.HSTSStats.SitesWithHSTS) / float64(metrics.TotalSites) * 100
		metrics.CSPStats.CSPPercentage = float64(metrics.CSPStats.SitesWithCSP) / float64(metrics.TotalSites) * 100
		metrics.CookieStats.AvgCookiesPerSite = float64(metrics.CookieStats.TotalCookies) / float64(metrics.TotalSites)
	}

	return metrics, nil
}

func PrintMetrics(metrics *SecurityMetrics) {
	fmt.Printf("\nSecurity Metrics Analysis\n")
	fmt.Printf("=======================\n\n")

	fmt.Printf("Total Sites Analyzed: %d\n\n", metrics.TotalSites)

	fmt.Printf("HSTS Implementation:\n")
	fmt.Printf("- Sites with HSTS: %d (%.1f%%)\n", metrics.HSTSStats.SitesWithHSTS, metrics.HSTSStats.HSTSPercentage)
	fmt.Printf("- HSTS Preload enabled: %d\n", metrics.HSTSStats.PreloadEnabled)
	fmt.Printf("- HSTS includeSubdomains: %d\n\n", metrics.HSTSStats.IncludeSubdomains)

	fmt.Printf("Content Security Policy:\n")
	fmt.Printf("- Sites with CSP: %d (%.1f%%)\n", metrics.CSPStats.SitesWithCSP, metrics.CSPStats.CSPPercentage)
	fmt.Printf("- unsafe-inline usage: %d\n", metrics.CSPStats.UnsafeInline)
	fmt.Printf("- unsafe-eval usage: %d\n", metrics.CSPStats.UnsafeEval)
	fmt.Printf("- Wildcard (*) sources: %d\n\n", metrics.CSPStats.WildcardSources)

	fmt.Printf("Cookie Security:\n")
	fmt.Printf("- Secure cookies: %d\n", metrics.CookieStats.SecureCookies)
	fmt.Printf("- HttpOnly cookies: %d\n", metrics.CookieStats.HttpOnlyCookies)
	fmt.Printf("- SameSite Strict: %d\n", metrics.CookieStats.SameSiteStrict)
	fmt.Printf("- SameSite Lax: %d\n", metrics.CookieStats.SameSiteLax)
	fmt.Printf("- SameSite None: %d\n\n", metrics.CookieStats.SameSiteNone)

	fmt.Printf("WordPress Security:\n")
	fmt.Printf("- WordPress sites: %d\n", metrics.WordPressStats.WordPressSites)
	fmt.Printf("- Vulnerable plugins: %d\n", metrics.WordPressStats.VulnerablePlugins)
	fmt.Printf("- Vulnerable themes: %d\n", metrics.WordPressStats.VulnerableThemes)
	fmt.Printf("- Total CVEs: %d\n", metrics.WordPressStats.CVECount)
	fmt.Printf("  - High severity: %d\n", metrics.WordPressStats.HighSeverity)
	fmt.Printf("  - Medium severity: %d\n", metrics.WordPressStats.MediumSeverity)
	fmt.Printf("  - Low severity: %d\n\n", metrics.WordPressStats.LowSeverity)

	fmt.Printf("TLS Configuration:\n")
	fmt.Printf("- Modern TLS (1.3): %d\n", metrics.TLSStats.ModernTLS)
	fmt.Printf("- Intermediate TLS (1.2): %d\n", metrics.TLSStats.IntermediateTLS)
	fmt.Printf("- Old TLS (≤1.1): %d\n", metrics.TLSStats.OldTLS)
	fmt.Printf("- Strong ciphers: %d\n", metrics.TLSStats.StrongCiphers)
	fmt.Printf("- Weak ciphers: %d\n", metrics.TLSStats.WeakCiphers)
} 