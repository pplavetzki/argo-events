package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

// ErrorResponse is the return interface for the api gateway
type ErrorResponse struct {
	Status int `json:"status"`
	Message string `json:"message"`
	Details interface{} `json:"details"`
}

// Options is a struct for specifying config options for the middleware
type Options struct {
	AuthEndpoint string
}

// JWTMw is a struct for using external auth for middleware
type JWTMw struct {
	Options Options
}

func OnError(w http.ResponseWriter, r *http.Request, err string) {
	http.Error(w, err, http.StatusUnauthorized)
}

// New constructs a new Secure instance with supplied options.
func NewJWTMw(options ...Options) *JWTMw {

	var opts Options
	if len(options) == 0 {
		opts = Options{}
	} else {
		opts = options[0]
	}

	return &JWTMw{
		Options: opts,
	}
}

func makeRequest(authEndpoint, token string) error {
	body := bytes.NewBufferString(token)
	r, err := http.Post(authEndpoint, "text/plain", body)
	if err != nil {
		return err
	}

	defer r.Body.Close()
	result, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		var er ErrorResponse
		jsErr := json.Unmarshal(result, &er)
		if jsErr != nil {
			return jsErr
		}
		log.Println(er)
		return errors.New("Failed to authenticate token.")
	}
	log.Println(fmt.Sprintf("%s", result))

	return nil
}

// CheckJWT verifies the token by calling external auth endpoint
func (m *JWTMw) CheckJWT(w http.ResponseWriter, r *http.Request) error {
	token, err := FromAuthHeader(r)
	if err != nil {
		return err
	}
	err = makeRequest(m.Options.AuthEndpoint, token)
	if err != nil {
		return err
	}

	return nil
}

func (m *JWTMw) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Let secure process the request. If it returns an error,
		// that indicates the request should not continue.
		err := m.CheckJWT(w, r)

		// If there was an error, do not continue.
		if err != nil {
			OnError(w, r, "Invalid Token!")
			return
		}

		h.ServeHTTP(w, r)
	})
}

// FromAuthHeader is a "TokenExtractor" that takes a give request and extracts
// the JWT token from the Authorization header.
func FromAuthHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("Authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}
