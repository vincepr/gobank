package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type ApiServer struct{
	listenAddr string
	storage Storage
}

func NewApiServer(listenAddr string, stor Storage) *ApiServer{
	return &ApiServer{
		listenAddr: listenAddr,
		storage: stor,
	}
}

// routing URL-paths using https://github.com/gorilla/mux
func (s *ApiServer) Run(){
	router := mux.NewRouter()
	router.HandleFunc("/login", wrapHandler(s.handleLogin))
	router.HandleFunc("/account", wrapHandler(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(wrapHandler(s.handleAccountWithParams), s.storage))
	router.HandleFunc("/transfer", wrapHandler(s.handleTransfer))

	log.Println("JSON-Api server running on port: ", s.listenAddr)
	http.ListenAndServe(s.listenAddr, router)
}

/**
* login HANDLERS 
*/
func (s *ApiServer) handleLogin(header http.ResponseWriter, r *http.Request) error{
	var request LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil{
		return err
	}

	account, err := s.storage.GetAccountByNumber(request.Number)
	if err != nil{
		return fmt.Errorf("account/password incorrect")
	}

	// check if password is correct? err = nil if so:
	err = bcrypt.CompareHashAndPassword([]byte(account.PasswordEnc), []byte(request.Password))
	if err != nil{
		return fmt.Errorf("account/password incorrect")
	}
	// create a new token for the users-session
	jwtToken, err := createJwtToken(account)
	if err != nil{
		return err
	}
	
	response :=  LoginResponseSuccess{
		Id: account.Id,
		Number: request.Number,
		JWTToken: jwtToken,
	}
	

	return WriteJSON(header, http.StatusOK, response)
}

/**
* account HANDLERS 
*/
func (s *ApiServer) handleAccount(header http.ResponseWriter, r *http.Request) error{
	switch r.Method{
	case "GET":
		return s.handleGetAccountsAll(header, r)
	case "POST":
		return s.handleCreateAccount(header, r)
	}
	return fmt.Errorf("method not supported: %s", r.Method)
} 
func (s *ApiServer) handleAccountWithParams(header http.ResponseWriter, r *http.Request) error{
	switch r.Method{
	case "GET":
		return s.handleGetAccountById(header, r)
	case "DELETE":
		return s.handleDeleteAccount(header, r)
	}
	return fmt.Errorf("method not supported: %s", r.Method)
}

func (s *ApiServer) handleGetAccountById(header http.ResponseWriter, r *http.Request) error{
	idInt, err := paramsToId(r)
	if err != nil{
		return err
	}
	account, err := s.storage.GetAccountById(idInt)
	if err != nil{
		return err
	}
	return WriteJSON(header, http.StatusOK, account)
} 

func (s *ApiServer) handleGetAccountsAll(header http.ResponseWriter, r *http.Request) error{
	accounts, err := s.storage.GetAccountsAll()
	if err != nil{
		return err
	}
	return WriteJSON(header, http.StatusOK, accounts)
} 

func (s *ApiServer) handleCreateAccount(header http.ResponseWriter, r *http.Request) error{
	// joink names from request and create a new account-struct with it
	request := &CreateAccountRequest{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil{
		return err
	}
	account, err := NewAccount(request.FirstName, request.LastName, request.Password)
	if err != nil{ 
		return err
	}
	// try pushing that valid acount data into the db
	if err := s.storage.CreateAccount(account);err != nil{
		return err
	}

	/*-lets just have the user login after creating an account, some validation might have to happen.
	// create a jwt token for further identification & auth so we can be logged in from the get-go
	tokenString, err :=createJwtToken(account)
	fmt.Println("JWT token:",tokenString)
	if err != nil{
		return err
	}
	*/

	return WriteJSON(header, http.StatusOK, account)
} 

func (s *ApiServer) handleDeleteAccount(header http.ResponseWriter, r *http.Request) error{
	//_, err := s.storage.DeleteAccount(id)
	id, err := paramsToId(r)
	if err != nil{
		return err
	}
	if err := s.storage.DeleteAccount(id); err != nil{
		return err
	}
	return WriteJSON(header, http.StatusOK, map[string]int{"deleted": id})
} 

/** 
* money-transaction HANDLERS 
*/
func (s *ApiServer) handleTransfer(header http.ResponseWriter, r *http.Request) error{
	trReq := &TransferRequest{}
	if err := json.NewDecoder(r.Body).Decode(trReq); err != nil{
		return err
	}
	defer r.Body.Close()

	return WriteJSON(header, http.StatusOK, trReq)
}

/** 
* HELPER- functions: 
*/
func WriteJSON(header http.ResponseWriter, status int, val any) error{
	header.Header().Set("Content-Type", "application/json")
	header.WriteHeader(status)
	return json.NewEncoder(header).Encode(val)
}

// Middleware for Auth: using Jason-Web-Token-standard - https://jwt.io/introduction
// jwt package from go get -u github.com/golang-jwt/jwt/v5
func withJWTAuth(handlerFunc http.HandlerFunc, storage Storage) http.HandlerFunc{
	return func(header http.ResponseWriter, r *http.Request){
		// check if there is ANY valid token:
		tokenString :=r.Header.Get("x-jwt-token")
		token, err := validateJWT(tokenString)					
		if (err != nil || !token.Valid) {
			WriteJSON(header, http.StatusForbidden, ApiError{Error: "invalid token"})
			return 
		}
		// identify user-nr that is beeing acessed
		userId, err := paramsToId(r)
		if (err != nil || !token.Valid) {
			WriteJSON(header, http.StatusForbidden, ApiError{Error: "invalid token"})
			return 
		}
		// grab that nr's data from the database
		account, err := storage.GetAccountById(userId)
		if (err != nil || !token.Valid) {
			WriteJSON(header, http.StatusForbidden, ApiError{Error: "invalid token"})
			return 
		}
		// check if the claims of the token fit the user-> user accessing his own data
		claims := token.Claims.(jwt.MapClaims)
		claimedNr := int64(claims["accountNumber"].(float64))	// comes out float64 out... 
		//... of the interface->cast it as int with float64 type assertion :todo rewrite with jwt map
		if account.Number !=  claimedNr{
			WriteJSON(header, http.StatusForbidden, ApiError{Error: "invalid token"})
			return 
		}

		handlerFunc(header, r)
	}
}

// validation happens here
func validateJWT(tokenString string)(*jwt.Token, error){
	//secret := os.Getenv("JWT_SECRET")	// in terminal for testing  $ export JWT_SECRET=qwert123
	secret := "SecretGoesBrrrrr"
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
	
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(secret), nil
	})
}

// creates a individual token to validate account users
func createJwtToken(account *Account)(string, error){
	mySigningKey := []byte("SecretGoesBrrrrr")

	// Create the Claims
	claims := &jwt.MapClaims{
		"expiresAt": jwt.NewNumericDate(time.Unix(1516239022, 0)),
		"accountNumber": account.Number,
		"issuer":    "gobank",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(mySigningKey)
}

type apiFunction func(http.ResponseWriter, *http.Request) error

type ApiError struct{
	Error string `json:"error"`
}

// the required structure of github.com/gorila/mux.NewRouter() doesn't allow for
// our error, so we handle it before in this wrapper, thus removing the return
func wrapHandler(f apiFunction) http.HandlerFunc{
	return func(header http.ResponseWriter, r *http.Request){
		if err := f(header, r); err != nil{
			// :todo handle error here properly
			WriteJSON(header, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

// mux.account/{id} -> parse string -> number with useful error msg on fail
func paramsToId(r *http.Request) (int, error){
	params := mux.Vars(r)["id"]
	idInt, err := strconv.Atoi(params)
	if err != nil{
		return idInt, fmt.Errorf("invalid id given: %s", params)
	}
	return idInt, err
}