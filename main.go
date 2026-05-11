package main

import (
	"embed"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/exto-saravanan/security-awareness-demo/sessions"
)

//go:embed static
var staticFiles embed.FS

func serveHTML(path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		f, err := staticFiles.ReadFile(path)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", f)
	}
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Landing page
	r.GET("/", serveHTML("static/index.html"))

	// ── Session 02 — Broken Access Control ───────────────────────────────────
	r.GET("/session/02", serveHTML("static/s02/index.html"))
	sessions.NewSession02().Register(r.Group("/session/02/api"))

	r.Run(":8090")
}
