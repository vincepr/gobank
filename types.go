package main

import (
	"math/rand"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type TransferRequest struct{
	ToAccount 	string	`json:"toAccount"`
	Ammount 	int	`json:"ammount"`
}

type LoginRequest struct{
	Iban 		string 	`json:"iban"`
	Password 	string 	`json:"password"`
}

type LoginResponseSuccess struct{
	Id 			int		`json:"id"`
	Iban		string	`json:"iban"`
	JWTToken	string	`json:"x-jwt-token"`
}

type CreateAccountRequest struct{
	FirstName 	string	`json:"firstName"`
	LastName 	string	`json:"lastName"`
	Password	string	`json:"password"`
}

type Account struct {
	Id 			int		`json:"id"`			//rename 'ID' -> 'id' in returned JSON
	FirstName 	string	`json:"firstName"`
	LastName 	string	`json:"lastName"`
	Iban 		string	`json:"iban"`
	PasswordEnc string	`json:"-"`			// `json:"-"` THIS WILL NOT GET "JSON-ed" !
	Balance 	int64	`json:"balance"`
	CreatedAt 	time.Time `json:"createdAt"`
}



func NewAccount(firstName, lastName, password string) (*Account, error){

	encPw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil{
		return nil, err
	}
	//fmt.Println("PASSWORD-Plain:", password, "PASSWORD-encrypted:", encPw)

	return &Account{
		//Id		// using databse autoincrement(in postgres serial)
		FirstName: firstName,
		LastName: lastName,
		Iban: "DE-"+strconv.Itoa(rand.Intn(99999)),													// :todo make sure this is unique at some point
		PasswordEnc: string(encPw),
		// Balance : 0 	//-> no need to specify this implicit because default is 0
		CreatedAt: time.Now().UTC(),
	}, nil
}