package middleware

import (
	"github.com/gofiber/fiber/v2"
)

// AdminAuth handles admin authentication
type AdminAuth struct {
	adminPassword string
}

// NewAdminAuth creates a new admin auth middleware
func NewAdminAuth(adminPassword string) *AdminAuth {
	return &AdminAuth{
		adminPassword: adminPassword,
	}
}

// AuthMiddleware returns the admin authentication middleware
func (a *AdminAuth) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// For now, use basic auth as a simple admin check
		// In production, this could be enhanced with sessions or tokens
		auth := c.Get("Authorization")
		if auth == "" {
			c.Set("WWW-Authenticate", "Basic realm=Admin")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Admin authentication required",
			})
		}

		// Simple password check - in production, use proper auth
		// TODO: implement Basic Auth
		// if auth != "Bearer "+a.adminPassword {
		// 	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		// 		"error": "Invalid admin credentials",
		// 	})
		// }

		return c.Next()
	}
}
