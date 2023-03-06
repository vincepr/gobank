package main

import (
	"fmt"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestNewAccount(t *testing.T){
	account, err := NewAccount("a", "b", "password")
	assert.Nil(t, err)

	fmt.Printf("%+v", account)
}