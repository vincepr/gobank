package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
*
*	JSON WEB TOKEN - Auth 	:todo exlude this to a module
*
 */

// Middleware for Auth: using Jason-Web-Token-standard - https://jwt.io/introduction
// jwt package from go get -u github.com/golang-jwt/jwt/v5
func middlewareJWTAuth(handlerFunc http.HandlerFunc, storage Storage) http.HandlerFunc{
	return func(header http.ResponseWriter, r *http.Request){
		// Default Error msg, so no info about if a account exists can be gathered
		writeJSONError := func(){
			WriteJSON(header, http.StatusForbidden, ApiError{Error: "invalid token"})
		}
		// check if there is ANY valid token:
		tokenString :=r.Header.Get("x-jwt-token")
		claims, err := validateJWTClaims(tokenString)					
		if (err != nil) {
			writeJSONError()
			return 
		}
		// identify user-nr that is beeing acessed from url {id}
		userId, err := paramsToId(r)
		if (err != nil) {
			writeJSONError()
			return 
		}
		// grab that nr's data from the database
		account, err := storage.GetAccountById(userId)
		if (err != nil) {
			writeJSONError()
			return 
		}
		// check if the claims of the token fit the user-> user accessing his own data
		claimedNr := claims.Iban
		if account.Iban !=  claimedNr{
			writeJSONError()
			return 
		}

		handlerFunc(header, r)
		
	}
}


// Claims from a Token, stores who the user is, what he can access and or and for how long 
type JWTClaims struct {
	Id int		`json:"id"`
	Iban string `json:"iban"`
	IsAdmin bool `json:"isAdmin"`
	jwt.RegisteredClaims
}

func NewJWTClaims(id int, iban string, isAdmin  bool) JWTClaims{
	return JWTClaims{
		Iban: iban,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(18 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "go-Auth",
			//Subject:   "somebody",
			//ID:        "1",
			//Audience:  []string{"somebody_else"},
		},
	}
}

// creates a Token to pass to our Users after ex. Login
func createJWTToken(id int, iban string, isAdmin bool) (string, error){
	mySigningKey := keyFromEnvForJWT()
	claims := NewJWTClaims(id, iban, isAdmin)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(mySigningKey)
}

// validation happens here, returns our claims
func validateJWTClaims(tokenString string) (*JWTClaims, error){
	mySigningKey := keyFromEnvForJWT()
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {	// Validate the encrypt-Algorythm is the one what we expect 
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(mySigningKey), nil
	})
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

// read the Secret-Key we use for encryption from env.
func keyFromEnvForJWT() []byte{
	key := os.Getenv("JWT_KEY")
	if key == "" {
		key = "DefaultSecretGoesBrrr"
		fmt.Println("Remainder - Dont forget to set your key, example $ export JWT_KEY=bhJas5_Sk-7El3VuCx7QerFuFS.Ns7bKBiJ_4O3deoZw")
	}
	return []byte(key)
}
