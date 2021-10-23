package models

import (
	"errors"

	"github.com/StarLight-Oliver/basic-auth-golang/database"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `json:"username" gorm:"unique"`
	Password string `json:"password"`
	Role     string
}

func (u *User) Create() error {
	result := database.DB.Create(&u)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (u *User) SetPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hash)
	return nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

func CheckUser(username, password string) (*User, error) {
	var user User
	result := database.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	if user.CheckPassword(password) {
		return &user, nil
	}
	return nil, errors.New("invalid username or password")
}
