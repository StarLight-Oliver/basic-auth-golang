package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type JwtWrapper struct {
	Secret          string
	Issuer          string
	ExpirationHours int64
}

type JwtClaims struct {
	UserID uint `json:"user_id"`
	jwt.StandardClaims
}

func (j *JwtWrapper) GenerateToken(userID uint) (string, error) {
	log.Println("Generating token")
	log.Printf("Time valid for %d hours", j.ExpirationHours)
	claims := &JwtClaims{
		UserID: userID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(j.ExpirationHours)).Unix(),
			Issuer:    j.Issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(j.Secret))
}

func (j *JwtWrapper) ValidateToken(tokenString string) (*JwtClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(j.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JwtClaims)

	if !ok {
		return nil, errors.New("invalid token")
	}

	fmt.Printf("%+v\n", claims)
	fmt.Printf("Current Time %v\n", time.Now().Unix())

	if !claims.VerifyExpiresAt(time.Now().Unix(), false) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

func (j *JwtWrapper) JwtMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// read the cookie from the request
		cookie, err := r.Cookie("AuthToken")
		if err != nil {
			if err == http.ErrNoCookie {
				// if the cookie is not set, return an unauthorized status
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// For any other type of error, return a bad request status
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// get the token from the cookie
		token := cookie.Value

		// validate the token
		claims, err := j.ValidateToken(token)
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(err.Error()))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		// set the user id in the request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user_id", claims.UserID)
		r = r.WithContext(ctx)

		// Generate a new token for the current user
		newToken, err := j.GenerateToken(claims.UserID)
		if err == nil {
			// set the new token as the users cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "AuthToken",
				Value:    newToken,
				Expires:  time.Now().Add(time.Hour * time.Duration(j.ExpirationHours)),
				HttpOnly: true,
			})
		}
		// call the next handler
		h.ServeHTTP(w, r)
	})
}
