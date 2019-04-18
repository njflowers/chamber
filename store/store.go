package store

import (
	"os"
	"errors"
	"time"
	"fmt"
	"strings"
)

type ChangeEventType int

const (
	Created ChangeEventType = iota
	Updated
)

func (c ChangeEventType) String() string {
	switch c {
	case Created:
		return "Created"
	case Updated:
		return "Updated"
	}
	return "unknown"
}

var (
	// ErrSecretNotFound is returned if the specified secret is not found in the
	// parameter store
	ErrSecretNotFound = errors.New("secret not found")
)

type SecretId struct {
	Service string
	Key     string
}

type Secret struct {
	Value *string
	Meta  SecretMetadata
}

// A secret without any metadata
type RawSecret struct {
	Value string
	Key   string
}

type SecretMetadata struct {
	Created   time.Time
	CreatedBy string
	Version   string
	Key       string
}

type ChangeEvent struct {
	Type    ChangeEventType
	Time    time.Time
	User    string
	Version string
}

type Store interface {
	Write(id SecretId, value string) error
	Read(id SecretId, version int) (Secret, error)
	List(service string, includeValues bool) ([]Secret, error)
	ListRaw(service string) ([]RawSecret, error)
	History(id SecretId) ([]ChangeEvent, error)
	Delete(id SecretId) error
}

func KMSKey() *string {
	chamberKey, ok := os.LookupEnv("CHAMBER_KMS_KEY_ALIAS")
	if !ok {
		return nil
	}
	if !strings.HasPrefix(chamberKey, "alias/") {
		chamberKey = fmt.Sprintf("alias/%s", chamberKey)
	}

	return &chamberKey
}

func(s Secret) toRawSecret() RawSecret {
	return RawSecret {
		Value: *s.Value,
		Key: s.Meta.Key,
	}
}

func idToName(id SecretId) string {
	return fmt.Sprintf("%s%s", serviceToPrefix(id.Service), id.Key)
}

func serviceToPrefix(service string) string {
	if shouldUsePaths() {
		return fmt.Sprintf("/%s/", service)
	}
	return fmt.Sprintf("%s.", service)
}

func shouldUsePaths() bool {
	_, ok := os.LookupEnv("CHAMBER_NO_PATHS")
	return !ok
}