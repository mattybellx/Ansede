// Expected: no finding (safe — has ownership check)
// Go Gin handler with proper ownership verification
package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AccountController struct {
	db *gorm.DB
}

func (ac *AccountController) GetAccount(c *gin.Context) {
	userID := c.GetString("user_id") // set by auth middleware
	accountID := c.Param("id")

	var account Account
	// Ownership check: only return if user owns this account
	result := ac.db.Where("id = ? AND owner_id = ?", accountID, userID).First(&account)
	if result.Error != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}

	c.JSON(200, account)
}
