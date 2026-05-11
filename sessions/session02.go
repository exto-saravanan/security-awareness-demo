package sessions

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ── Data ─────────────────────────────────────────────────────────────────────

type s02User struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Salary int    `json:"salary"`
}

var s02Seed = []s02User{
	{1, "Alice", "alice@exto360.com", "engineer", 85000},
	{2, "Bob", "bob@exto360.com", "engineer", 92000},
	{3, "Carol", "carol@exto360.com", "admin", 120000},
}

// ── Session ──────────────────────────────────────────────────────────────────

type Session02 struct {
	vulnerable bool
	users      []s02User
}

func NewSession02() *Session02 {
	s := &Session02{vulnerable: true}
	s.reset()
	return s
}

func (s *Session02) Register(rg *gin.RouterGroup) {
	rg.GET("/mode", s.getMode)
	rg.POST("/mode", s.toggleMode)
	rg.GET("/users/:id/profile", s.getProfile)
	rg.GET("/admin/reports", s.adminReports)
	rg.PUT("/users/:id/role", s.updateRole)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func (s *Session02) reset() {
	s.users = make([]s02User, len(s02Seed))
	copy(s.users, s02Seed)
}

func (s *Session02) find(id int) *s02User {
	for i := range s.users {
		if s.users[i].ID == id {
			return &s.users[i]
		}
	}
	return nil
}

func (s *Session02) actor(c *gin.Context) *s02User {
	id, err := strconv.Atoi(c.GetHeader("X-User-ID"))
	if err != nil {
		return nil
	}
	return s.find(id)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func (s *Session02) getMode(c *gin.Context) {
	mode := "fixed"
	if s.vulnerable {
		mode = "vulnerable"
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

func (s *Session02) toggleMode(c *gin.Context) {
	s.vulnerable = !s.vulnerable
	s.reset()
	mode := "fixed"
	if s.vulnerable {
		mode = "vulnerable"
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

// Scenario 1 — IDOR: fetch any user profile by swapping the ID
func (s *Session02) getProfile(c *gin.Context) {
	actor := s.actor(c)
	if actor == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated — select a user above"})
		return
	}
	targetID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if !s.vulnerable && actor.ID != targetID && actor.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "access denied",
			"fix":   "requester.ID must equal target.ID, or requester.Role must be admin",
		})
		return
	}
	target := s.find(targetID)
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, *target)
}

// Scenario 2 — Missing authorization: authenticated != authorized
func (s *Session02) adminReports(c *gin.Context) {
	actor := s.actor(c)
	if actor == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	if !s.vulnerable && actor.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "access denied",
			"fix":   "requester.Role must be admin",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"report": "Q1 Security Incidents",
		"incidents": []gin.H{
			{"id": 1, "title": "Exposed API key in repository", "severity": "critical", "status": "resolved"},
			{"id": 2, "title": "IDOR on /api/users/:id", "severity": "high", "status": "open"},
			{"id": 3, "title": "Missing rate limit on /auth/login", "severity": "medium", "status": "in-review"},
		},
		"note": "Confidential — admin access only",
	})
}

// Scenario 3 — Privilege escalation: any user can promote themselves
func (s *Session02) updateRole(c *gin.Context) {
	actor := s.actor(c)
	if actor == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}
	targetID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var body struct {
		Role string `json:"role" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is required"})
		return
	}
	if !s.vulnerable && actor.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "access denied",
			"fix":   "only admin can modify user roles",
		})
		return
	}
	target := s.find(targetID)
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	oldRole := target.Role
	target.Role = body.Role
	c.JSON(http.StatusOK, gin.H{
		"message":  "role updated",
		"user":     target.Name,
		"old_role": oldRole,
		"new_role": body.Role,
	})
}
