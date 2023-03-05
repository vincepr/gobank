package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
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

func (s *ApiServer) Run(){
	router := mux.NewRouter()
	router.HandleFunc("/account", wrapHandler(s.handleAccount))
	router.HandleFunc("/account/", wrapHandler(s.handleAccount))
	router.HandleFunc("/account/{id}", wrapHandler(s.handleAccountWithParams))
	router.HandleFunc("/transfer", wrapHandler(s.handleTransfer))

	log.Println("JSON-Api server running on port: ", s.listenAddr)
	http.ListenAndServe(s.listenAddr, router)
}

/**
* account HANDLERS 
*/
func (s *ApiServer) handleAccount(header http.ResponseWriter,r *http.Request) error{
	switch r.Method{
	case "GET":
		return s.handleGetAccountsAll(header, r)
	case "POST":
		return s.handleCreateAccount(header, r)
	case "DELETE":
		return s.handleDeleteAccount(header, r)
	}
	return fmt.Errorf("method not supported: %s", r.Method)
} 
func (s *ApiServer) handleAccountWithParams(header http.ResponseWriter,r *http.Request) error{
	switch r.Method{
	case "GET":
		return s.handleGetAccountById(header, r)
	case "POST":
		return s.handleCreateAccount(header, r)
	case "DELETE":
		return s.handleDeleteAccount(header, r)
	}
	return fmt.Errorf("method not supported: %s", r.Method)
}

func (s *ApiServer) handleGetAccountById(header http.ResponseWriter,r *http.Request) error{
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

func (s *ApiServer) handleGetAccountsAll(header http.ResponseWriter,r *http.Request) error{
	accounts, err := s.storage.GetAccountsAll()
	if err != nil{
		return err
	}
	return WriteJSON(header, http.StatusOK, accounts)
} 

func (s *ApiServer) handleCreateAccount(header http.ResponseWriter,r *http.Request) error{
	// joink names from request and create a new account-struct with it
	request := &CreateAccountRequest{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil{
		return err
	}
	account := NewAccount(request.FirstName, request.LastName)
	// try pushing that full-valid acount data into the db
	if err := s.storage.CreateAccount(account);err != nil{
		return err
	}
	return WriteJSON(header, http.StatusOK, account)
} 

func (s *ApiServer) handleDeleteAccount(header http.ResponseWriter,r *http.Request) error{
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
func (s *ApiServer) handleTransfer(header http.ResponseWriter,r *http.Request) error{
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
			// :todo handle error here
			WriteJSON(header, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

// parse string -> number with useful error msg on fail
func paramsToId(r *http.Request) (int, error){
	params := mux.Vars(r)["id"]
	idInt, err := strconv.Atoi(params)
	if err != nil{
		return idInt, fmt.Errorf("invalid id given: %s", params)
	}
	return idInt, err
}