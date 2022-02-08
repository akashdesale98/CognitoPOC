package auth

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	// cip "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

type CognitoClient struct {
	AppClientId  string
	UserPoolId   string
	ClientSecret string
	*cognitoidentityprovider.CognitoIdentityProvider
}

func Init() *CognitoClient {
	// Load the Shared AWS Configuration (~/.aws/config)
	// cfg, err := config.LoadDefaultConfig(context.Background())
	// if err != nil {
	// 	panic(err)
	// }

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1")})
	if err != nil {
		panic(err)
	}

	return &CognitoClient{
		os.Getenv("COGNITO_APP_CLIENT_ID"),
		os.Getenv("COGNITO_USER_POOL_ID"),
		os.Getenv("CLIENT_SECRET"),
		// cip.NewFromConfig(cfg),
		cognitoidentityprovider.New(sess),
	}
}
