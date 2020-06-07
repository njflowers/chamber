package store

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
)

const (
	RegionEnvVar            = "CHAMBER_AWS_REGION"
	CustomSSMEndpointEnvVar = "CHAMBER_AWS_SSM_ENDPOINT"
)

func getSession(numRetries int) (*session.Session, *string, error) {
	var region *string

	endpointResolver := func(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
		customSsmEndpoint, ok := os.LookupEnv(CustomSSMEndpointEnvVar)
		if ok {
			return endpoints.ResolvedEndpoint{
				URL: customSsmEndpoint,
			}, nil
		}

		return endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
	}

	if regionOverride, ok := os.LookupEnv(RegionEnvVar); ok {
		region = aws.String(regionOverride)
	}
	retSession, err := session.NewSessionWithOptions(
		session.Options{
			Config: aws.Config{
				Region:           region,
				MaxRetries:       aws.Int(numRetries),
				EndpointResolver: endpoints.ResolverFunc(endpointResolver),
			},
			SharedConfigState: session.SharedConfigEnable,
		},
	)
	if err != nil {
		return nil, nil, err
	}

	// If region is still not set, attempt to determine it via ec2 metadata API
	if aws.StringValue(retSession.Config.Region) == "" {
		session := session.New()
		ec2metadataSvc := ec2metadata.New(session)
		if regionOverride, err := ec2metadataSvc.Region(); err == nil {
			region = aws.String(regionOverride)
		}
	}

	return retSession, region, nil
}

// validPathKeyFormat is the format that is expected for key names inside parameter store
// when using paths
var validPathKeyFormat = regexp.MustCompile(`^(\/[\w\-\.]+)+$`)

// validKeyFormat is the format that is expected for key names inside parameter store when
// not using paths
var validKeyFormat = regexp.MustCompile(`^[\w\-\.]+$`)

func validateName(name string, usePaths bool) bool {
	if usePaths {
		return validPathKeyFormat.MatchString(name)
	}
	return validKeyFormat.MatchString(name)
}

type keyConverter func(string) string

func idToName(id SecretId, usePaths bool) string {
	return fmt.Sprintf("%s%s", serviceToPrefix(id.Service, usePaths), id.Key)
}

func nameToID(name string, usePaths bool) SecretId {
	service, key := nameToServiceAndKey(name, usePaths)
	return SecretId {
		Service: service,
		Key: key,
	}
}

func nameToServiceAndKey(name string, usePaths bool) (string, string) {
	delimiter := "."
	if usePaths {
		delimiter = "/"

		// Trim leading slash
		name = name[1:]
	}

	splitIdx := strings.LastIndex(name, delimiter)
	return name[:splitIdx], name[splitIdx+1:]
}

func serviceToPrefix(service string, usePaths bool) string {
	if usePaths {
		return fmt.Sprintf("/%s/", service)
	}
	return fmt.Sprintf("%s.", service)
}

func shouldUsePaths() bool {
	_, ok := os.LookupEnv("CHAMBER_NO_PATHS")
	return !ok
}

func keys(m map[string]Secret, converter keyConverter) []string {
	keys := []string{}
	for k := range m {
		val := k
		if converter != nil {
			val = converter(val)
		}
		keys = append(keys, val)
	}
	return keys
}

func values(m map[string]Secret) []Secret {
	values := []Secret{}
	for _, v := range m {
		values = append(values, v)
	}
	return values
}