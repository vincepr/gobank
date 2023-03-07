package main

import (
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct{
	Number 		int64 	`json:"iban"`
	Password 	string 	`json:"password"`
}

type LoginResponseSuccess struct{
	Id 			int		`json:"id"`
	Number		int64	`json:"iban"`
	JWTToken	string	`json:"x-jwt-token"`
}

type TransferRequest struct{
	ToAccount 	int	`json:"toAccount"`
	Ammount 	int	`json:"ammount"`
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
	Number 		int64	`json:"iban"`
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
		Number: int64(rand.Intn(9999999)),
		PasswordEnc: string(encPw),
		// Balance : 0 	//-> no need to specify this implicit because default is 0
		CreatedAt: time.Now().UTC(),
	}, nil
}