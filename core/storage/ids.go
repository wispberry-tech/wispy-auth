package storage

import (
	"fmt"

	"github.com/google/uuid"
)

func newUUID() (uuid.UUID, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate UUID: %w", err)
	}
	return id, nil
}
