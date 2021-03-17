package helpers

import "github.com/gin-gonic/gin"

const (
	NotFound                  = "not found"
	ServerError               = "server error"
	OK                        = "OK"
	AccessControlAllowMethods = "Access-Control-Allow-Methods"
	CORSMethodsOptPost        = "OPTIONS, POST"
)

// Simple404 sets a quick and easy 400 gin response
func Simple404(c *gin.Context) {
	c.Data(404, "text/plain", []byte(NotFound))
}

// Simple500 sets a quick and easy 500 gin response
func Simple500(c *gin.Context) {
	c.Data(500, "text/plain", []byte(ServerError))
}

// Simple200OK sets a quick and easy gin response, typically used for Options
// preflight CORS requests
func Simple200OK(c *gin.Context) {
	c.Data(200, "text/plain", []byte(OK))
}

// SetCORSMethods sets Options and Post headers for CORS
func SetCORSMethods(c *gin.Context) {
	c.Header(AccessControlAllowMethods, CORSMethodsOptPost)
}
