package main

import (
	"math/rand"
	"time"
)

type TransferRequest struct{
	ToAccount 	int	`json:"toAccount"`
	Ammount 	int	`json:"ammount"`
}

type CreateAccountRequest struct{
	FirstName string	`json:"firstName"`
	LastName string	`json:"lastName"`
}

type Account struct {
	Id 			int		`json:"id"`			//rename 'ID' -> 'id' in returned JSON
	FirstName 	string	`json:"firstName"`
	LastName 	string	`json:"lastName"`
	Number 		int64	`json:"iban"`
	Balance 	int64	`json:"balance"`
	CreatedAt 	time.Time `json:"createdAt"`
}

func NewAccount(firstName, lastName string) *Account{
	return &Account{
		//Id		// using databse autoincrement(in postgres serial)
		FirstName: firstName,
		LastName: lastName,
		Number: int64(rand.Intn(10000000)),
		// Balance : 0 	//-> no need to specify this implicit because default is 0
		CreatedAt: time.Now().UTC(),
	}
}