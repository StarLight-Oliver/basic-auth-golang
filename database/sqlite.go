package database

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Init() (err error) {
	DB, err = gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	return
}
