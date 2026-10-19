package server

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/lianyis/dntrace/trace"
)

func cacheClearHandler(c *gin.Context) {
	trace.ClearCaches()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
