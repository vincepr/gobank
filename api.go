package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

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
	router.HandleFunc("/account/{id}", middlewareJWTAuth(wrapHandler(s.handleAccountWithParams), s.storage))
	router.HandleFunc("/transfer", wrapHandler(s.handleTransfer))

	log.Println("JSON-Api server running on port: ", s.listenAddr)
	http.ListenAndServe(s.listenAddr, router)
}

/**
* 	/login HANDLER 
*/

func (s *ApiServer) handleLogin(header http.ResponseWriter, r *http.Request) error{
	var request LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil{
		return err
	}
	// check if account exist?
	account, err := s.storage.GetAccountByIban(request.Iban)
	if err != nil{
		return fmt.Errorf("account/password incorrect")
	}
	// check if password is correct?
	err = bcrypt.CompareHashAndPassword([]byte(account.PasswordEnc), []byte(request.Password))
	if err != nil{
		return fmt.Errorf("account/password incorrect")
	}
	// create a new token for the users-session
	jwtToken, err := createJWTToken(account.Id ,account.Iban, account.IsAdmin)
	if err != nil{
		return err
	}
	response :=  LoginResponseSuccess{
		Id: account.Id,
		Iban: request.Iban,
		JWTToken: jwtToken,
	}
	return WriteJSON(header, http.StatusOK, response)
}

/**
* 	/account and /account/{id} HANDLERS 
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



