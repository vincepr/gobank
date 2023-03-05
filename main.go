package main

import (
	"fmt"
	"log"
)

func main() {
	store, err := NewPostgresStore()
	if err != nil{
		log.Fatal(err)
	}

	if err :=store.Init(); err !=nil{
		log.Fatal(err)
	}

	server := NewApiServer(":3000", store)
	server.Run()
	fmt.Println("Yeah running")
}