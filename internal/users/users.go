package users

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	LastLoginAt  time.Time `json:"last_login_at"`
}

type UserManager struct {
	mu       sync.RWMutex
	users    map[string]*User
	filePath string
}

func NewUserManager(filePath string) (*UserManager, error) {
	um := &UserManager{
		users:    make(map[string]*User),
		filePath: filePath,
	}
	if err := um.load(); err != nil {
		return nil, err
	}
	return um, nil
}

func (um *UserManager) load() error {
	um.mu.Lock()
	defer um.mu.Unlock()

	data, err := os.ReadFile(um.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, &um.users)
}

func (um *UserManager) save() error {
	um.mu.RLock()
	defer um.mu.RUnlock()

	data, err := json.MarshalIndent(um.users, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(um.filePath, data, 0644)
}

func (um *UserManager) Register(email, password string) error {
	um.mu.Lock()
	defer um.mu.Unlock()

	if _, exists := um.users[email]; exists {
		return errors.New("user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &User{
		Email:        email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	um.users[email] = user
	// Release lock temporarily to save? No, save takes read lock.
	// We need to implement save carefully or just inline it to avoid deadlock/race since we hold Lock.
	// Let's just write file directly here or use a helper that expects lock to be held.
	// Refactor save to executeSave and call it.

	// Quick inline save for simplicity and safety against deadlocks in this context
	data, err := json.MarshalIndent(um.users, "", "  ")
	if err != nil {
		delete(um.users, email) // Rollback
		return err
	}
	if err := os.WriteFile(um.filePath, data, 0644); err != nil {
		delete(um.users, email) // Rollback
		return err
	}

	return nil
}

func (um *UserManager) Login(email, password string) (*User, error) {
	um.mu.Lock() // Write lock to update LastLoginAt
	defer um.mu.Unlock()

	user, exists := um.users[email]
	if !exists {
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	user.LastLoginAt = time.Now()

	// Inline save
	data, _ := json.MarshalIndent(um.users, "", "  ")
	os.WriteFile(um.filePath, data, 0644)

	return user, nil
}
