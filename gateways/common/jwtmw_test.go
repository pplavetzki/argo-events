package common

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

var JWT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NjE0MTkwNDYsInVzZXIiOnsidXNlck5hbWUiOiJhZG1pbiIsInNjb3BlIjoiYWRtaW5pc3RyYXRvciJ9LCJpc3MiOiJuZXQuanVuaXBlci5wcy5hdXRvbWF0aW9uIiwiYXVkIjoiamVkaSIsInN1YiI6InVzZXItYWNjb3VudCIsImlhdCI6MTU2MTQxODQ0Nn0.hsR-ZLmWwHa222Ah3hCM7XGXz_Ww-iXe9ttZ16pj4X0QWjGcpCsJS_IJZWJfL6aO0B8Wl3at2t9xexsY1Z7dRpWxKLQBhOqKDDv-ogPetDNPRpDKo88ivNUaLJTSFa8V95Xm1zePlZgh57dqBcCVGYV01wajgnHRINhOplUGl2QGRasct9lsoALddKYrE3Y5hXrxFBxpZPna0Um9mI9kBl1ZXlin88gQXLYEZbtGeo56uTGL_OF_gwSh5drSPT34JRAyIy9eeka9xKc0HxaOJKIfv1ZDdK8T6CwXju_aw_4FM2Q2sA4o4K49UcG8Uaqf0LJMuUzmVQMrh7npuD-FaA"

func TestNew(t *testing.T) {
	authEnpoint := "http://localhost:9191/api/authorize/verify-token"
	want := New(Options{AuthEndpoint: authEnpoint})
	if want.Options.AuthEndpoint != authEnpoint {
		t.Error("Did not instantiate JWTMw correctly")
	}
}

func TestJWTMw_CheckJWT(t *testing.T) {
	authEnpoint := "http://localhost:9191/api/authorize/verify-token"
	want := New(Options{AuthEndpoint: authEnpoint})
	r, _ := http.NewRequest("post", authEnpoint, nil)
	r.Header.Set("Authorization", fmt.Sprintf("bearer %v", JWT_TOKEN))
	w := httptest.NewRecorder()

	err := want.CheckJWT(w, r)
	if err != nil {
		t.Error("Failed to process token!")
	}
}
