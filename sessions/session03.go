package sessions

import (
	"encoding/json"
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ── Data ─────────────────────────────────────────────────────────────────────

var s03Accounts = map[string]string{
	"alice": "pass123",
	"bob":   "letmein",
	"admin": "sup3rs3cr3t",
}

var s03Roles = map[string]string{
	"alice": "engineer",
	"bob":   "engineer",
	"admin": "admin",
}

type s03Comment struct {
	Author  string `json:"author"`
	Content string `json:"content"`
}

// ── Session ──────────────────────────────────────────────────────────────────

type Session03 struct {
	vulnerable bool
	comments   []s03Comment
}

func NewSession03() *Session03 {
	s := &Session03{vulnerable: true}
	s.reset()
	return s
}

func (s *Session03) reset() {
	s.comments = []s03Comment{
		{Author: "alice", Content: "Great session last week!"},
		{Author: "bob", Content: "Really helpful, thanks."},
	}
}

func (s *Session03) Register(rg *gin.RouterGroup) {
	rg.GET("/mode", s.getMode)
	rg.POST("/mode", s.toggleMode)
	rg.POST("/login", s.login)
	rg.GET("/comments", s.getComments)
	rg.POST("/comments", s.postComment)
	rg.POST("/register", s.register)
}

// ── Mode ──────────────────────────────────────────────────────────────────────

func (s *Session03) getMode(c *gin.Context) {
	mode := "fixed"
	if s.vulnerable {
		mode = "vulnerable"
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

func (s *Session03) toggleMode(c *gin.Context) {
	s.vulnerable = !s.vulnerable
	s.reset()
	mode := "fixed"
	if s.vulnerable {
		mode = "vulnerable"
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// Scenario 1 — NoSQL Injection: operator object in password field bypasses auth
func (s *Session03) login(c *gin.Context) {
	raw, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not read body"})
		return
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	usernameRaw, hasUser := payload["username"]
	passwordRaw, hasPass := payload["password"]
	if !hasUser || !hasPass {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password required"})
		return
	}

	var username string
	if err := json.Unmarshal(usernameRaw, &username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username must be a string"})
		return
	}

	var password string
	passwordIsString := json.Unmarshal(passwordRaw, &password) == nil

	if !s.vulnerable {
		if !passwordIsString {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid input — authentication failed",
				"fix":   "password must be a string — operator objects rejected at the type boundary",
			})
			return
		}
	}

	// Operator injection bypass (vulnerable mode only)
	if !passwordIsString {
		if role, ok := s03Roles[username]; ok {
			c.JSON(http.StatusOK, gin.H{
				"authenticated": true,
				"user":          username,
				"role":          role,
				"note":          `operator injection: {"$gt": ""} bypassed password check — no credential needed`,
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"authenticated": true,
				"user":          "admin",
				"role":          "admin",
				"note":          "operator matched first document regardless of username",
			})
		}
		return
	}

	// Normal credential check
	if expected, ok := s03Accounts[username]; ok && expected == password {
		c.JSON(http.StatusOK, gin.H{
			"authenticated": true,
			"user":          username,
			"role":          s03Roles[username],
		})
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
}

// Scenario 2 — Stored XSS: raw content returned vs HTML-encoded output
func (s *Session03) getComments(c *gin.Context) {
	if s.vulnerable {
		c.JSON(http.StatusOK, gin.H{"comments": s.comments})
		return
	}
	safe := make([]s03Comment, len(s.comments))
	for i, cmt := range s.comments {
		safe[i] = s03Comment{
			Author:  html.EscapeString(cmt.Author),
			Content: html.EscapeString(cmt.Content),
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"comments": safe,
		"fix":      "content HTML-encoded on output — < > \" & replaced with entities before leaving the server",
	})
}

func (s *Session03) postComment(c *gin.Context) {
	var body s03Comment
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "author and content required"})
		return
	}
	s.comments = append(s.comments, body)
	c.JSON(http.StatusOK, gin.H{
		"message":   "comment stored",
		"stored_as": body.Content,
	})
}

// Scenario 3 — Input Validation: unguarded fields vs type/length/range/format checks
func (s *Session03) register(c *gin.Context) {
	raw, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not read body"})
		return
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
		return
	}

	if s.vulnerable {
		c.JSON(http.StatusOK, gin.H{
			"message":  "user registered",
			"received": payload,
			"note":     "no validation applied — operator objects, negative ages, and malformed emails all accepted",
		})
		return
	}

	usernameRaw, hasU := payload["username"]
	ageRaw, hasA := payload["age"]
	emailRaw, hasE := payload["email"]
	if !hasU || !hasA || !hasE {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username, age, and email are required"})
		return
	}

	var username string
	if err := json.Unmarshal(usernameRaw, &username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "username must be a string",
			"fix":   "type validation rejected non-string value",
		})
		return
	}
	if len(username) < 1 || len(username) > 32 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "username must be 1–32 characters",
			"fix":   "length validation applied",
		})
		return
	}

	var age float64
	if err := json.Unmarshal(ageRaw, &age); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "age must be a number",
			"fix":   "type validation rejected non-numeric value",
		})
		return
	}
	if age < 1 || age > 120 || age != float64(int(age)) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "age must be a whole number between 1 and 120",
			"fix":   "range validation applied — 1–120 only",
		})
		return
	}

	var email string
	if err := json.Unmarshal(emailRaw, &email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "email must be a string",
			"fix":   "type validation rejected non-string value",
		})
		return
	}
	if !emailRe.MatchString(email) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid email format",
			"fix":   "format validation: must match user@domain.tld",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "user registered",
		"username": username,
		"email":    email,
		"age":      int(age),
		"fix":      "all fields passed type, length, range, and format validation",
	})
}
