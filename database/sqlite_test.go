package database

import (
	"testing"
)

func TestInitDatabase(t *testing.T) {
	err := Init()

	if err != nil {
		t.Errorf("Error initializing database: %s", err)
	}

	// assert.NoError(t, err)
}
