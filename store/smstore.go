package store

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

// ensure SMStore confirms to Store interface
var _ Store = &SMStore{}

// SMStore implements the Store interface for storing secrets in Secrets Manager
type SMStore struct {
	sm      		secretsmanageriface.SecretsManagerAPI
	ssm      		ssmiface.SSMAPI
	kmsKeyID		*string
	usePaths		bool
	useSSM			bool
}

// NewSMStore creates a new SMStore
func NewSMStore(numRetries int, useSSM bool) (*SMStore, error) {
	session, region, err := getSession(numRetries)
	if err != nil {
		return nil, err
	}

	sm := secretsmanager.New(session, &aws.Config{
		MaxRetries: aws.Int(numRetries),
		Region:     region,
	})

	ssm := ssm.New(session, &aws.Config{
		MaxRetries: aws.Int(numRetries),
		Region:     region,
	})

	return &SMStore{
		sm:      	sm,
		ssm:		ssm,
		kmsKeyID:	KMSKey(),
		usePaths:	true,
		useSSM:		useSSM,
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
	secrets := map[string]Secret { }
	
	for {
		listSecretsInput := &secretsmanager.ListSecretsInput {
			NextToken: nextToken,
		}

		result, err := s.sm.ListSecrets(listSecretsInput);

		if err != nil {
			return []Secret{}, err
		}
		
		for _, entry := range result.SecretList {
			fullName := *entry.Name;

			if !validateName(fullName, s.usePaths) {
				continue
			}

			svc, key := nameToServiceAndKey(fullName, s.usePaths)
			version := getCurrentVersion(*entry)
			if svc == service {
				secrets[fullName] = Secret {
					Value: nil,
					Meta: SecretMetadata {
						Created: *entry.LastChangedDate,
						Key: key,
						Version: version,
					},
				}
			}
		}

		nextToken = result.NextToken
		if nextToken == nil {
			break
		}
	}

	if s.useSSM {
		const smPrefix = "/aws/reference/secretsmanager/"
		
		if includeValues {
			// Use AWS Systems Manager's passthrough feature to pull values
			secretKeys := keys(secrets, func(k string) string {
				return fmt.Sprintf("%s%s", smPrefix, k)
			})

			if secretValues, err := getParameters(s.ssm, secretKeys); err != nil {
				return []Secret {}, err
			} else {
				for key, secret := range secrets {
					secret.Value = new(string)
					*secret.Value = secretValues[fmt.Sprintf("%s%s", smPrefix, key)]
					secrets[key] = secret
				}
			}
		}
	} else {
		// Use SecretsManager APIs to pull values
		for key, _ := range secrets {
			id := nameToID(key, s.usePaths)
			if result, err := s.readSecret(id, -1, includeValues); err != nil {
				return []Secret {}, err
			} else {
				secrets[key] = result
			}
		}
	}

	return values(secrets), nil
}

func (s *SMStore) readSecret(id SecretId, versionId int, includeValue bool) (Secret, error) {
	var version *string
	if versionId != -1 {
		version = aws.String(strconv.Itoa(versionId))
	}

	getSecretValueInput := &secretsmanager.GetSecretValueInput {
		SecretId:	aws.String(idToName(id, s.usePaths)),
		VersionId: 	version,
	}

	result, err := s.sm.GetSecretValue(getSecretValueInput)

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
		Name: 			aws.String(idToName(id, s.usePaths)),
		SecretString: 	aws.String(value),
		KmsKeyId:		s.kmsKeyID,
	}

	_, err := s.sm.CreateSecret(createSecretInput)
	return err
}

func (s *SMStore) updateSecret(id SecretId, value string) error {
	updateSecretInput := &secretsmanager.UpdateSecretInput {
		SecretId:		aws.String(idToName(id, s.usePaths)),
		SecretString:	aws.String(value),
		KmsKeyId:		s.kmsKeyID,
	}

	_, err := s.sm.UpdateSecret(updateSecretInput)
	return err
}

func (s *SMStore) deleteSecret(id SecretId) error {
	deleteSecretInput := &secretsmanager.DeleteSecretInput {
		SecretId: aws.String(idToName(id, s.usePaths)),
	}

	_, err := s.sm.DeleteSecret(deleteSecretInput)
	return err
}

func (s *SMStore) listChangeEvents(id SecretId) ([]ChangeEvent, error) {
	changeEvents := []ChangeEvent { }
	listSecretVersionIdsInput := &secretsmanager.ListSecretVersionIdsInput {
		SecretId: 			aws.String(idToName(id, s.usePaths)),
		IncludeDeprecated:	aws.Bool(true),
	}

	results, err := s.sm.ListSecretVersionIds(listSecretVersionIdsInput)
	if err != nil {
		return changeEvents, err
	}

	// Pre-sort by version created date
	versions := results.Versions
	sort.SliceStable(versions, func(i, j int) bool {
		return versions[i].CreatedDate.Before(*versions[j].CreatedDate)
	})

	changeType := Created
	for _, entry := range versions {
		event := ChangeEvent {
			Type:		changeType,
			Time:		*entry.CreatedDate,
			Version: 	*entry.VersionId,
		}

		changeEvents = append(changeEvents, event)
		changeType = Updated
	}

	return changeEvents, nil
}

func getCurrentVersion(secret secretsmanager.SecretListEntry) string {
	version := ""
	for v, stages := range secret.SecretVersionsToStages {
		for _, stage := range stages {
			if *stage == "AWSCURRENT" {
				version = v
			}
		}
	}

	return version
}