package store

import (
	"strings"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

// ensure SMStore confirms to Store interface
var _ Store = &SMStore{}

// SMStore implements the Store interface for storing secrets in Secrets Manager
type SMStore struct {
	svc      		secretsmanageriface.SecretsManagerAPI
	kmsKeyID		*string
}

// NewSMStore creates a new SMStore
func NewSMStore(numRetries int) (*SMStore, error) {
	session, region, err := getSession(numRetries)
	if err != nil {
		return nil, err
	}

	svc := secretsmanager.New(session, &aws.Config{
		MaxRetries: aws.Int(numRetries),
		Region:     region,
	})

	return &SMStore{
		svc:      	svc,
		kmsKeyID:	KMSKey(),
	}, nil
}

func (s *SMStore) Write(id SecretId, value string) error {
	return s.writeSecret(id, value)
}

func (s *SMStore) Read(id SecretId, version int) (Secret, error) {
	return s.readSecret(id, version, true)
}

func (s *SMStore) Delete(id SecretId) error {
	return s.deleteSecret(id)
}

func (s *SMStore) List(service string, includeValues bool) ([]Secret, error) {
	return s.listSecrets(service, includeValues)
}

func (s *SMStore) ListRaw(service string) ([]RawSecret, error) {
	return s.listRawSecrets(service)
}

func (s *SMStore) History(id SecretId) ([]ChangeEvent, error) {
	return s.listChangeEvents(id)
}

func (s *SMStore) listRawSecrets(service string) ([]RawSecret, error) {
	rawSecrets := []RawSecret { }
	
	if secrets, err := s.listSecrets(service, true); err != nil {
		return rawSecrets, err
	} else {
		for _, entry := range secrets {
			rawSecrets = append(rawSecrets, entry.toRawSecret())
		}

		return rawSecrets, nil
	}
}

func (s *SMStore) listSecrets(service string, includeValues bool) ([]Secret, error) {
	var nextToken *string = nil
	secretPrefix := serviceToPrefix(service)
	secrets := []Secret { }
	
	for {
		listSecretsInput := &secretsmanager.ListSecretsInput {
			NextToken: nextToken,
		}

		result, err := s.svc.ListSecrets(listSecretsInput);

		if err != nil {
			return []Secret{}, err
		} else {
			for _, entry := range result.SecretList {
				name := *entry.Name;

				if strings.HasPrefix(name, secretPrefix) {
					id := SecretId {
						Service: service,
						Key: name[len(secretPrefix):],
					}

					if secret, err := s.readSecret(id, -1, includeValues); err != nil {
						return []Secret {}, err
					} else {
						secrets = append(secrets, secret) 
					}
				}
			}
		}

		nextToken = result.NextToken
		if nextToken == nil {
			break
		}
	}

	return secrets, nil
}

func (s *SMStore) readSecret(id SecretId, versionId int, includeValue bool) (Secret, error) {
	var version *string
	if versionId != -1 {
		version = aws.String(strconv.Itoa(versionId))
	}

	getSecretValueInput := &secretsmanager.GetSecretValueInput {
		SecretId:	aws.String(idToName(id)),
		VersionId: 	version,
	}

	result, err := s.svc.GetSecretValue(getSecretValueInput)

	if err != nil {
		return Secret{}, err
	}

	var value *string
	if includeValue {
		value = result.SecretString
	}

	secret := Secret {
		Value: value,
		Meta: SecretMetadata {
			Created: *result.CreatedDate,
			Version: *result.VersionId,
			Key: (*result.Name)[len(id.Service)+1:],
		},
	}
	
	return secret, nil
}

func (s *SMStore) writeSecret(id SecretId, value string) error {
	if _, err := s.readSecret(id, -1, false); err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == secretsmanager.ErrCodeResourceNotFoundException {
			return s.createSecret(id, value)
		} else {
			return err
		}
	} else {
		return s.updateSecret(id, value)
	}
}

func (s *SMStore) createSecret(id SecretId, value string) error {
	createSecretInput := &secretsmanager.CreateSecretInput {
		Name: 			aws.String(idToName(id)),
		SecretString: 	aws.String(value),
		KmsKeyId:		s.kmsKeyID,
	}

	_, err := s.svc.CreateSecret(createSecretInput)
	return err
}

func (s *SMStore) updateSecret(id SecretId, value string) error {
	updateSecretInput := &secretsmanager.UpdateSecretInput {
		SecretId:		aws.String(idToName(id)),
		SecretString:	aws.String(value),
		KmsKeyId:		s.kmsKeyID,
	}

	_, err := s.svc.UpdateSecret(updateSecretInput)
	return err
}

func (s *SMStore) deleteSecret(id SecretId) error {
	deleteSecretInput := &secretsmanager.DeleteSecretInput {
		SecretId: aws.String(idToName(id)),
	}

	_, err := s.svc.DeleteSecret(deleteSecretInput)
	return err
}

func (s *SMStore) listChangeEvents(id SecretId) ([]ChangeEvent, error) {
	changeEvents := []ChangeEvent { }
	listSecretVersionIdsInput := &secretsmanager.ListSecretVersionIdsInput {
		SecretId: 			aws.String(idToName(id)),
		IncludeDeprecated:	aws.Bool(true),
	}

	if results, err := s.svc.ListSecretVersionIds(listSecretVersionIdsInput); err != nil {
		return changeEvents, err
	} else {
		for _, entry := range results.Versions {
			event := ChangeEvent {
				Type:		Updated,
				Time:		*entry.LastAccessedDate,
				Version: 	*entry.VersionId,
			}

			changeEvents = append(changeEvents, event)
		}
	}

	return changeEvents, nil
}