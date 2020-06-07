package store

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

// ensure SSMStore confirms to Store interface
var _ Store = &SSMStore{}

// SSMStore implements the Store interface for storing secrets in SSM Parameter
// Store
type SSMStore struct {
	svc      		ssmiface.SSMAPI
	usePaths 		bool
	kmsKeyID		string
}

// NewSSMStore creates a new SSMStore
func NewSSMStore(numRetries int) (*SSMStore, error) {
	ssmSession, region, err := getSession(numRetries)
	if err != nil {
		return nil, err
	}

	svc := ssm.New(ssmSession, &aws.Config{
		MaxRetries: aws.Int(numRetries),
		Region:     region,
	})

	var kmsKeyID string = "alias/parameter_store_key"
	if key := KMSKey(); key != nil {
		kmsKeyID = *key
	}

	return &SSMStore{
		svc:      		svc,
		usePaths: 		shouldUsePaths(),
		kmsKeyID: 		kmsKeyID,
	}, nil
}

// Write writes a given value to a secret identified by id.  If the secret
// already exists, then write a new version.
func (s *SSMStore) Write(id SecretId, value string) error {
	version := 1
	// first read to get the current version
	current, err := s.Read(id, -1)
	if err != nil && err != ErrSecretNotFound {
		return err
	}
	if err == nil {
		if thisVersion, err := strconv.Atoi(current.Meta.Version); err == nil {
			version = thisVersion + 1
		}
	}

	putParameterInput := &ssm.PutParameterInput{
		KeyId:       aws.String(s.kmsKeyID),
		Name:        aws.String(s.idToName(id)),
		Type:        aws.String("SecureString"),
		Value:       aws.String(value),
		Overwrite:   aws.Bool(true),
		Description: aws.String(strconv.Itoa(version)),
	}

	// This API call returns an empty struct
	_, err = s.svc.PutParameter(putParameterInput)
	if err != nil {
		return err
	}

	return nil
}

// Read reads a secret from the parameter store at a specific version.
// To grab the latest version, use -1 as the version number.
func (s *SSMStore) Read(id SecretId, version int) (Secret, error) {
	if version == -1 {
		return s.readLatest(id)
	}

	return s.readVersion(id, version)
}

// Delete removes a secret from the parameter store. Note this removes all
// versions of the secret.
func (s *SSMStore) Delete(id SecretId) error {
	// first read to ensure parameter present
	_, err := s.Read(id, -1)
	if err != nil {
		return err
	}

	deleteParameterInput := &ssm.DeleteParameterInput{
		Name: aws.String(s.idToName(id)),
	}

	_, err = s.svc.DeleteParameter(deleteParameterInput)
	if err != nil {
		return err
	}

	return nil
}

func (s *SSMStore) readVersion(id SecretId, version int) (Secret, error) {
	getParameterHistoryInput := &ssm.GetParameterHistoryInput{
		Name:           aws.String(s.idToName(id)),
		WithDecryption: aws.Bool(true),
	}

	var result Secret
	if err := s.svc.GetParameterHistoryPages(getParameterHistoryInput, func(o *ssm.GetParameterHistoryOutput, lastPage bool) bool {
		for _, history := range o.Parameters {
			thisVersion := 0
			if history.Description != nil {
				thisVersion, _ = strconv.Atoi(*history.Description)
			}
			if thisVersion == version {
				result = Secret{
					Value: history.Value,
					Meta: SecretMetadata{
						Created:   *history.LastModifiedDate,
						CreatedBy: *history.LastModifiedUser,
						Version:   strconv.Itoa(thisVersion),
						Key:       *history.Name,
					},
				}
				return false
			}
		}
		return true
	}); err != nil {
		return Secret{}, ErrSecretNotFound
	}
	if result.Value != nil {
		return result, nil
	}

	return Secret{}, ErrSecretNotFound
}

func (s *SSMStore) readLatest(id SecretId) (Secret, error) {
	getParametersInput := &ssm.GetParametersInput{
		Names:          []*string{aws.String(s.idToName(id))},
		WithDecryption: aws.Bool(true),
	}

	resp, err := s.svc.GetParameters(getParametersInput)
	if err != nil {
		return Secret{}, err
	}

	if len(resp.Parameters) == 0 {
		return Secret{}, ErrSecretNotFound
	}
	param := resp.Parameters[0]
	var parameter *ssm.ParameterMetadata
	var describeParametersInput *ssm.DescribeParametersInput

	// To get metadata, we need to use describe parameters

	if s.usePaths {
		// There is no way to use describe parameters to get a single key
		// if that key uses paths, so instead get all the keys for a path,
		// then find the one you are looking for :(
		describeParametersInput = &ssm.DescribeParametersInput{
			ParameterFilters: []*ssm.ParameterStringFilter{
				{
					Key:    aws.String("Path"),
					Option: aws.String("OneLevel"),
					Values: []*string{aws.String(basePath(s.idToName(id)))},
				},
			},
		}
	} else {
		describeParametersInput = &ssm.DescribeParametersInput{
			Filters: []*ssm.ParametersFilter{
				{
					Key:    aws.String("Name"),
					Values: []*string{aws.String(s.idToName(id))},
				},
			},
			MaxResults: aws.Int64(1),
		}
	}
	if err := s.svc.DescribeParametersPages(describeParametersInput, func(o *ssm.DescribeParametersOutput, lastPage bool) bool {
		for _, param := range o.Parameters {
			if *param.Name == s.idToName(id) {
				parameter = param
				return false
			}
		}
		return true
	}); err != nil {
		return Secret{}, err
	}

	if parameter == nil {
		return Secret{}, ErrSecretNotFound
	}

	secretMeta := parameterMetaToSecretMeta(parameter)

	return Secret{
		Value: param.Value,
		Meta:  secretMeta,
	}, nil
}

// List lists all secrets for a given service.  If includeValues is true,
// then those secrets are decrypted and returned, otherwise only the metadata
// about a secret is returned.
func (s *SSMStore) List(service string, includeValues bool) ([]Secret, error) {
	secrets := map[string]Secret{}

	var describeParametersInput *ssm.DescribeParametersInput
	if s.usePaths {
		describeParametersInput = &ssm.DescribeParametersInput{
			ParameterFilters: []*ssm.ParameterStringFilter{
				{
					Key:    aws.String("Path"),
					Option: aws.String("OneLevel"),
					Values: []*string{aws.String("/" + service)},
				},
			},
		}
	} else {
		describeParametersInput = &ssm.DescribeParametersInput{
			Filters: []*ssm.ParametersFilter{
				{
					Key:    aws.String("Name"),
					Values: []*string{aws.String(service + ".")},
				},
			},
		}
	}

	err := s.svc.DescribeParametersPages(describeParametersInput, func(resp *ssm.DescribeParametersOutput, lastPage bool) bool {
		for _, meta := range resp.Parameters {
			if !validateName(*meta.Name, s.usePaths) {
				continue
			}
			secretMeta := parameterMetaToSecretMeta(meta)
			secrets[secretMeta.Key] = Secret{
				Value: nil,
				Meta:  secretMeta,
			}
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	if includeValues {
		secretKeys := keys(secrets, nil)
		
		if secretValues, err := getParameters(s.svc, secretKeys); err != nil {
			return nil, err
		} else {
			for key, secret := range secrets {
				secret.Value = new(string)
				*secret.Value = secretValues[key]
				secrets[key] = secret
			}
		}
	}

	return values(secrets), nil
}

// ListRaw lists all secrets keys and values for a given service. Does not include any
// other meta-data. Uses faster AWS APIs with much higher rate-limits. Suitable for
// use in production environments.
func (s *SSMStore) ListRaw(service string) ([]RawSecret, error) {
	if s.usePaths {
		secrets := map[string]RawSecret{}
		getParametersByPathInput := &ssm.GetParametersByPathInput{
			Path:           aws.String("/" + service + "/"),
			WithDecryption: aws.Bool(true),
		}

		err := s.svc.GetParametersByPathPages(getParametersByPathInput, func(resp *ssm.GetParametersByPathOutput, lastPage bool) bool {
			for _, param := range resp.Parameters {
				if !validateName(*param.Name, s.usePaths) {
					continue
				}

				secrets[*param.Name] = RawSecret{
					Value: *param.Value,
					Key:   *param.Name,
				}
			}
			return true
		})

		if err != nil {
			// If the error is an access-denied exception
			awsErr, isAwserr := err.(awserr.Error)
			if isAwserr {
				if awsErr.Code() == "AccessDeniedException" && strings.Contains(awsErr.Message(), "is not authorized to perform: ssm:GetParametersByPath on resource") {
					// Fall-back to using the old list method in case some users haven't updated their IAM permissions yet, but warn about it and
					// tell them to fix their permissions
					fmt.Fprintf(
						os.Stderr,
						"Warning: %s\nFalling-back to using ssm:DescribeParameters. This may cause delays or failures due to AWS rate-limiting.\n"+
							"This is behavior deprecated and will be removed in a future version of chamber. Please update your IAM permissions to grant ssm:GetParametersByPath.\n\n",
						awsErr)

					// Delegate to List
					return s.listRawViaList(service)
				}
			}

			return nil, err
		}

		rawSecrets := make([]RawSecret, len(secrets))
		i := 0
		for _, rawSecret := range secrets {
			rawSecrets[i] = rawSecret
			i += 1
		}
		return rawSecrets, nil
	}

	// Delete to List (which uses the DescribeParameters API)
	return s.listRawViaList(service)
}

// History returns a list of events that have occurred regarding the given
// secret.
func (s *SSMStore) History(id SecretId) ([]ChangeEvent, error) {
	events := []ChangeEvent{}

	getParameterHistoryInput := &ssm.GetParameterHistoryInput{
		Name:           aws.String(s.idToName(id)),
		WithDecryption: aws.Bool(false),
	}

	if err := s.svc.GetParameterHistoryPages(getParameterHistoryInput, func(o *ssm.GetParameterHistoryOutput, lastPage bool) bool {
		for _, history := range o.Parameters {
			// Disregard error here, if Atoi fails (secret created outside of
			// Chamber), then we use version 0
			version := 0
			if history.Description != nil {
				version, _ = strconv.Atoi(*history.Description)
			}
			events = append(events, ChangeEvent{
				Type:    getChangeType(version),
				Time:    *history.LastModifiedDate,
				User:    *history.LastModifiedUser,
				Version: strconv.Itoa(version),
			})
		}
		return true
	}); err != nil {
		return events, ErrSecretNotFound
	}

	return events, nil
}

func (s *SSMStore) listRawViaList(service string) ([]RawSecret, error) {
	// Delegate to List
	secrets, err := s.List(service, true)

	if err != nil {
		return nil, err
	}

	rawSecrets := make([]RawSecret, len(secrets))
	for i, secret := range secrets {
		rawSecrets[i] = RawSecret{
			Key: secret.Meta.Key,

			// This dereference is safe because we trust List to have given us the values
			// that we asked-for
			Value: *secret.Value,
		}
	}

	return rawSecrets, nil
}

func getParameters(s ssmiface.SSMAPI, secretKeys []string) (map[string]string, error) {
	secrets := map[string]string {}
	
	for i := 0; i < len(secretKeys); i += 10 {
		batchEnd := i + 10
		if i+10 > len(secretKeys) {
			batchEnd = len(secretKeys)
		}
		batch := secretKeys[i:batchEnd]

		getParametersInput := &ssm.GetParametersInput{
			Names:          stringsToAWSStrings(batch),
			WithDecryption: aws.Bool(true),
		}

		resp, err := s.GetParameters(getParametersInput)
		if err != nil {
			return nil, err
		}

		for _, param := range resp.Parameters {
			secrets[*param.Name] = *param.Value
		}
	}

	return secrets, nil
}

func (s *SSMStore) idToName(id SecretId) string {
	return idToName(id, s.usePaths)
}

func basePath(key string) string {
	pathParts := strings.Split(key, "/")
	if len(pathParts) == 1 {
		return pathParts[0]
	}
	end := len(pathParts) - 1
	return strings.Join(pathParts[0:end], "/")
}

func parameterMetaToSecretMeta(p *ssm.ParameterMetadata) SecretMetadata {
	version := 0
	if p.Description != nil {
		version, _ = strconv.Atoi(*p.Description)
	}
	return SecretMetadata{
		Created:   *p.LastModifiedDate,
		CreatedBy: *p.LastModifiedUser,
		Version:   strconv.Itoa(version),
		Key:       *p.Name,
	}
}

func stringsToAWSStrings(slice []string) []*string {
	ret := []*string{}
	for _, s := range slice {
		ret = append(ret, aws.String(s))
	}
	return ret
}

func getChangeType(version int) ChangeEventType {
	if version == 1 {
		return Created
	}
	return Updated
}