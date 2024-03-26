package phpass_test

import (
	"fmt"
	"github.com/7836246/phpass-go/phpass"
	"testing"
)

func TestPasswordHashing(t *testing.T) {
	plainPassword := "123456"

	// Create a new PasswordHash instance with an iteration count of 8 and portable hash set to true
	ph := phpass.NewPasswordHash(16, true)

	// Hash the plain password
	hashedPassword, salt, err := ph.HashPassword(plainPassword)
	fmt.Println(hashedPassword, salt)
	if err != nil {
		t.Fatalf("Error hashing password: %v", err)
	}
	// Check if the plain password matches the hashed password
	if !ph.CheckPassword(plainPassword, hashedPassword) {
		t.Fatal("Password check failed")
	}
}
