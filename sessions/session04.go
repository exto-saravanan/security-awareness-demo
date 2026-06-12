package sessions

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ── Data ─────────────────────────────────────────────────────────────────────

var s04PublicFiles = map[string]string{
	"config.json": `{"app": "security-demo", "version": "1.0.0", "env": "production"}`,
	"readme.txt":  "Welcome to the Security Awareness Demo Lab.",
}

var s04SensitiveFiles = map[string]string{
	"../../etc/passwd":         "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:/usr/sbin/nologin\nadmin:x:1000:1000:/home/admin:/bin/bash",
	"../private/secrets.env":  "DB_PASSWORD=sup3rs3cr3t\nAPI_KEY=sk-prod-abc123xyz\nJWT_SECRET=insecure-jwt-secret",
	"../config/database.yml":  "host: db.internal\nuser: app_user\npassword: dbpass123\ndatabase: production",
}

type s04Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	CVE     string `json:"cve,omitempty"`
	CVSS    string `json:"cvss,omitempty"`
	FixedIn string `json:"fixed_in,omitempty"`
	Status  string `json:"status"`
}

type s04CVE struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Package  string `json:"package"`
	Summary  string `json:"summary"`
	FixedIn  string `json:"fixed_in"`
}

// ── Session ───────────────────────────────────────────────────────────────────

type Session04 struct {
	vulnerable bool
}

func NewSession04() *Session04 {
	return &Session04{vulnerable: true}
}

func (s *Session04) Register(rg *gin.RouterGroup) {
	rg.GET("/mode", s.getMode)
	rg.POST("/mode", s.toggleMode)
	rg.GET("/file", s.readFile)
	rg.GET("/audit", s.auditDeps)
	rg.GET("/scan", s.scanImage)
}

// ── Mode ──────────────────────────────────────────────────────────────────────

func (s *Session04) getMode(c *gin.Context) {
	mode := "fixed"
	if s.vulnerable {
		mode = "vulnerable"
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

func (s *Session04) toggleMode(c *gin.Context) {
	s.vulnerable = !s.vulnerable
	mode := "fixed"
	if s.vulnerable {
		mode = "vulnerable"
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// Scenario 1 — Path traversal via vulnerable file-serving library
func (s *Session04) readFile(c *gin.Context) {
	path := c.Query("path")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path parameter required"})
		return
	}

	if !s.vulnerable {
		if strings.Contains(path, "..") || strings.Contains(path, "/") || strings.Contains(path, "\\") {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid path — directory traversal rejected",
				"fix":   "updated library validates the resolved path stays within the allowed directory — traversal sequences rejected before any file lookup",
			})
			return
		}
		if content, ok := s04PublicFiles[path]; ok {
			c.JSON(http.StatusOK, gin.H{"path": path, "content": content})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	// Vulnerable: path passed directly to lookup without sanitisation
	if content, ok := s04PublicFiles[path]; ok {
		c.JSON(http.StatusOK, gin.H{"path": path, "content": content})
		return
	}
	if content, ok := s04SensitiveFiles[path]; ok {
		c.JSON(http.StatusOK, gin.H{
			"path":    path,
			"content": content,
			"note":    "path traversal succeeded — vulnerable library did not sanitise the path before resolving it",
		})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
}

// Scenario 2 — Dependency audit (SCA scan simulation)
func (s *Session04) auditDeps(c *gin.Context) {
	if s.vulnerable {
		c.JSON(http.StatusOK, gin.H{
			"scanned": false,
			"note":    "no SCA tooling configured — dependency tree not scanned for CVEs",
			"packages": []s04Package{
				{Name: "lodash", Version: "4.17.15", CVE: "CVE-2021-23337", CVSS: "7.2 HIGH", FixedIn: "4.17.21", Status: "VULNERABLE"},
				{Name: "axios", Version: "0.21.0", CVE: "CVE-2021-3749", CVSS: "7.5 HIGH", FixedIn: "0.21.2", Status: "VULNERABLE"},
				{Name: "log4j-core", Version: "2.14.1", CVE: "CVE-2021-44228", CVSS: "10.0 CRITICAL", FixedIn: "2.17.1", Status: "VULNERABLE"},
				{Name: "minimist", Version: "1.2.5", CVE: "CVE-2021-44906", CVSS: "9.8 CRITICAL", FixedIn: "1.2.6", Status: "VULNERABLE"},
				{Name: "express", Version: "4.17.1", Status: "OK"},
				{Name: "react", Version: "17.0.2", Status: "OK"},
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scanned": true,
		"fix":     "SCA scan completed — all direct and transitive dependencies checked against NVD and OSV databases on every build",
		"packages": []s04Package{
			{Name: "lodash", Version: "4.17.21", Status: "OK"},
			{Name: "axios", Version: "0.27.2", Status: "OK"},
			{Name: "log4j-core", Version: "2.20.0", Status: "OK"},
			{Name: "minimist", Version: "1.2.8", Status: "OK"},
			{Name: "express", Version: "4.18.2", Status: "OK"},
			{Name: "react", Version: "18.2.0", Status: "OK"},
		},
	})
}

// Scenario 3 — Container base image scan (Trivy-style simulation)
func (s *Session04) scanImage(c *gin.Context) {
	if s.vulnerable {
		c.JSON(http.StatusOK, gin.H{
			"image": "node:16-buster",
			"note":  "base image last pulled 18 months ago — OS packages not updated since original pull",
			"summary": gin.H{
				"critical": 3,
				"high":     12,
				"medium":   28,
				"low":      41,
			},
			"findings": []s04CVE{
				{ID: "CVE-2023-0286", Severity: "CRITICAL", Package: "openssl", Summary: "X.400 type confusion in X.509 GeneralName — remote code execution", FixedIn: "3.0.8"},
				{ID: "CVE-2022-1292", Severity: "CRITICAL", Package: "openssl", Summary: "c_rehash command injection — arbitrary command execution", FixedIn: "1.1.1o"},
				{ID: "CVE-2021-3711", Severity: "CRITICAL", Package: "openssl", Summary: "SM2 decryption buffer overflow — heap memory corruption", FixedIn: "1.1.1l"},
				{ID: "CVE-2023-29469", Severity: "HIGH", Package: "libxml2", Summary: "Use-after-free on empty string hash — potential DoS", FixedIn: "2.10.4"},
				{ID: "CVE-2022-40303", Severity: "HIGH", Package: "libxml2", Summary: "Integer overflow in XML_SKIP_BOM — heap buffer over-read", FixedIn: "2.10.3"},
				{ID: "CVE-2023-1255", Severity: "HIGH", Package: "openssl", Summary: "AES-XTS input buffer over-read — DoS via crafted message", FixedIn: "3.0.9"},
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"image": "node:20-alpine3.18",
		"fix":   "minimal base image — Alpine 3.18 with only required OS packages, rebuilt weekly in CI",
		"summary": gin.H{
			"critical": 0,
			"high":     0,
			"medium":   1,
			"low":      2,
		},
		"findings": []s04CVE{
			{ID: "CVE-2023-52425", Severity: "MEDIUM", Package: "expat", Summary: "CPU exhaustion from chained entity references — DoS only, no RCE", FixedIn: "2.6.0"},
		},
	})
}
