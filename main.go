package main

import (
	"cognitoPoc/pkg/auth"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	cip "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func main() {
	cognitoClient := auth.Init()

	r := chi.NewRouter()
	r.Use(middleware.Logger, middleware.WithValue("CognitoClient", cognitoClient))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome"))
	})

	r.Post("/signup", signUp2)

	r.Post("/signin", signIn2)

	r.Post("/verify", verifyToken2)

	port := os.Getenv("PORT")

	fmt.Println("starting server!")
	http.ListenAndServe(fmt.Sprintf(":%s", port), r)
}

type SignUpRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type SignInRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SignInResponse struct {
	// The access token.
	AccessToken *string `json:"access_token"`

	// The expiration period of the authentication result in seconds.
	ExpiresIn *int64 `json:"expires_in"`

	// The ID token.
	IdToken *string `json:"id_token"`

	// The refresh token.
	RefreshToken *string `json:"refresh_token"`

	// The token type.
	TokenType *string `json:"token_type"`
}

func signUp2(w http.ResponseWriter, r *http.Request) {
	// parse the request body
	var req SignUpRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get client from context
	cognitoClient, ok := r.Context().Value("CognitoClient").(*auth.CognitoClient)
	if !ok {
		http.Error(w, "Could not retrieve CognitoClient from context", http.StatusInternalServerError)
		return
	}

	userInput := &cip.SignUpInput{
		Username: aws.String(req.Username),
		Password: aws.String(req.Password),
		ClientId: aws.String(cognitoClient.AppClientId),
		UserAttributes: []*cip.AttributeType{ //TODO - add UUID as custom attribute; add country code as custom attribute
			{
				Name:  aws.String("custom:role"),
				Value: aws.String(req.Role),
			},
		},
	}

	_, err = cognitoClient.SignUp(userInput)
	if err != nil {
		log.Println("Error creating user: ", err.Error())
	}

	fmt.Println("err0", err)
	confirmInput := &cip.AdminConfirmSignUpInput{
		UserPoolId: aws.String(cognitoClient.UserPoolId),
		Username:   aws.String(req.Username),
	}

	// auto confirm all users.
	_, err = cognitoClient.AdminConfirmSignUp(confirmInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// call SignUp cognito API

	w.Write([]byte("signup!"))
}

func signIn2(w http.ResponseWriter, r *http.Request) {
	// parse the request body
	var req SignInRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get client from context
	cognitoClient, ok := r.Context().Value("CognitoClient").(*auth.CognitoClient)
	if !ok {
		http.Error(w, "Could not retrieve CognitoClient from context", http.StatusInternalServerError)
		return
	}
	initiateAuthInput := cip.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(req.Username),
			"PASSWORD": aws.String(req.Password),
		},
		ClientId: aws.String(cognitoClient.AppClientId),
	}
	// call InitiateAuth cognito API
	output, err := cognitoClient.InitiateAuth(&initiateAuthInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
		// return nil, err
	}
	// return initiateOutput, nil
	res := &SignInResponse{
		AccessToken:  output.AuthenticationResult.AccessToken,
		ExpiresIn:    output.AuthenticationResult.ExpiresIn,
		IdToken:      output.AuthenticationResult.IdToken,
		RefreshToken: output.AuthenticationResult.RefreshToken,
		TokenType:    output.AuthenticationResult.TokenType,
	}
	_ = json.NewEncoder(w).Encode(res)
}

func verifyToken2(w http.ResponseWriter, r *http.Request) {
	var req SignUpRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	authHeader := r.Header.Get("Authorization")
	splitAuthHeader := strings.Split(authHeader, " ")
	if len(splitAuthHeader) != 2 {
		http.Error(w, "Missing or invalid authorization header", http.StatusBadRequest)
		return
	}
	log.Println("auth", authHeader)
	// Get client from context
	cognitoClient, ok := r.Context().Value("CognitoClient").(*auth.CognitoClient)
	if !ok {
		http.Error(w, "Could not retrieve CognitoClient from context", http.StatusInternalServerError)
		return
	}

	pubKeyURL := "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"
	formattedURL := fmt.Sprintf(pubKeyURL, os.Getenv("AWS_DEFAULT_REGION"), cognitoClient.UserPoolId)

	keySet, err := jwk.Fetch(r.Context(), formattedURL)
	log.Println("err", keySet, err)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := jwt.Parse(
		[]byte(splitAuthHeader[1]),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
	)
	log.Println("err1", err)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	username, _ := token.Get("cognito:username")
	role, _ := token.Get("custom:role")

	if role == "owner" {
		log.Println("updating")
		input := &cip.AdminUpdateUserAttributesInput{
			UserPoolId: aws.String(cognitoClient.UserPoolId),
			Username:   aws.String(req.Username),
			UserAttributes: []*cip.AttributeType{
				{
					Name:  aws.String("custom:role"),
					Value: aws.String(req.Role),
				},
			},
		}

		_, err = cognitoClient.AdminUpdateUserAttributes(input)
		log.Println("updating err", err)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Don't have permission", http.StatusForbidden)
		return
	}

	fmt.Printf("The username: %v\n", username)
	fmt.Printf("The username: %v\n", role)
	fmt.Println(token)

	// Success return 200
	w.Write([]byte("verified!"))

}
