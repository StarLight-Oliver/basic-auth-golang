package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"github.com/StarLight-Oliver/basic-auth-golang/auth"
	"github.com/StarLight-Oliver/basic-auth-golang/database"
	"github.com/StarLight-Oliver/basic-auth-golang/models"
)

func main() {

	router := mux.NewRouter()

	database.Init()

	database.DB.AutoMigrate(&models.User{})

	jwtLogin := auth.JwtWrapper{
		Secret:          os.Getenv("JWT_SECRET"),
		ExpirationHours: 24,
		Issuer:          "starlight-oliver",
	}

	router.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user := models.User{
			Username: username,
		}

		user.SetPassword(password)

		var existingUser models.User

		result := database.DB.Where("username = ?", username).First(&existingUser)

		if result.Error == nil {
			fmt.Fprintf(w, "User already exists")
			return
		}

		err := user.Create()
		if err != nil {
			log.Println(err)

			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal server error"))

			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("User created"))

	}).Methods("POST")

	router.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// get the username and password from the request body
		username := r.FormValue("username")
		password := r.FormValue("password")

		// check if the username and password are correct

		user, err := models.CheckUser(username, password)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		token, err := jwtLogin.GenerateToken(user.ID)

		if err != nil {
			http.Error(w, "Error generating token", 500)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "AuthToken",
			Value:    token,
			Expires:  time.Now().Add(time.Hour * time.Duration(jwtLogin.ExpirationHours)),
			HttpOnly: true,
			// Secure:   true,
		})

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Successfully logged in"))
	}).Methods("POST")

	protect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Successfully accessed protected resource"))
	})

	router.Handle("/protected", jwtLogin.JwtMiddleware(protect))

	fmt.Println("Listening on port 8080")

	log.Fatal(http.ListenAndServe(":8080", router))
}
