package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

/*
* interface will make switching database or supporting
* multiple dbs at once easy
 */
type Storage interface {
	CreateAccount(*Account) error
	UpdateAccount(*Account) error
	DeleteAccount(int) error
	GetAccountById(int) (*Account, error)
	GetAccountsAll() ([]*Account, error)
}

/**
* PostgressStore as one db implementation of a Storage. (runs in docker, check README.md)
*/
type PostgresStore struct{
	db *sql.DB
}

func NewPostgresStore()(*PostgresStore, error){
	connStr := "user=postgres dbname=postgres password=password sslmode=disable"
	db, err := sql.Open("postgres",connStr)
	if err != nil{
		return nil, err
	}
	if err := db.Ping(); err != nil{
		return nil, err
	}
	return &PostgresStore{
		db: db,
	}, nil
}

func (st *PostgresStore) Init() error{
	return st.createAccountTable()
}

func (st *PostgresStore) createAccountTable() error{
	sqlStatement := `

	drop table IF EXISTS account;

	create table if not exists account (
		id serial PRIMARY KEY,
		first_name varchar(50) NOT NULL,
		last_name varchar(50) NOT NULL,
		number varchar(50),
		balance real,
		created_at timestamp
	);`

	_, err := st.db.Exec(sqlStatement)
	return err
}

func (st *PostgresStore) CreateAccount(a *Account) error{
	sqlStatement := `
	INSERT INTO account (first_name, last_name, number, balance, created_at)
	VALUES ($1, $2, $3, $4, $5);`
	_, err := st.db.Query(
		sqlStatement, 
		a.FirstName, a.LastName, a.Number, a.Balance, a.CreatedAt,
	)
	if err != nil{
		return err
	}
	//fmt.Printf("USER-CREATED: %+v \n", response)
	return err
}

func (st *PostgresStore) UpdateAccount(*Account) error{
	return nil
}

func (st *PostgresStore) DeleteAccount(id int) error{
	// :todo remove this hard delete and just flag it deleted
	// and dont show it in searches anymore
	sqlStatement := `DELETE FROM account where id = $1`
	_, err := st.db.Query(sqlStatement, id)
	return err
}

func (st *PostgresStore) GetAccountById(id int) (*Account, error){
	sqlStatement := `
	SELECT * FROM account
	WHERE id = $1`
	
	rows, err := st.db.Query(sqlStatement, id)
	if err != nil{
		return nil, err
	}

	for rows.Next(){
		return fromSqlReadAccount(rows)
	}
	return nil, fmt.Errorf("account %d not found.", id)
}

func (st *PostgresStore) GetAccountsAll() ([]*Account, error){
	rows, err := st.db.Query("SELECT * FROM account")
	if err != nil {
		return nil, err
	}
	accounts := []*Account{}
	for rows.Next(){
		account, err := fromSqlReadAccount(rows)
		if err != nil{
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// read sql-data (1row) and create the Account-type instance 
func fromSqlReadAccount(rows *sql.Rows) (*Account, error){
	account := &Account{}
	err := rows.Scan(
		&account.Id, 
		&account.FirstName, 
		&account.LastName, 
		&account.Number, 
		&account.Balance, 
		&account.CreatedAt,
	)
	return account, err
}