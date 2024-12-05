package main

import (
  "database/sql"
  "fmt"

  _ "github.com/lib/pq"
)

const (
  host     = "db"
  port     = 5432
  user     = "postgres"
  dbname   = "postgres"
)


func establishConnect() *sql.DB {
 	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password='' dbname=%s sslmode=disable", host, port, user, dbname)
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
        return nil
    }

    err = db.Ping()
    if err != nil {
        return nil
    }

    return db
}

func registerUser(uuid string, username string, hashed_password string) error {
	var s = ""
	err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&s)

	if (err != sql.ErrNoRows && err != nil) || s != ""{
        return err
    }

	_, err = db.Exec("INSERT INTO users (id, username, password, ext) VALUES ($1, $2, $3, '')", uuid, username, hashed_password)

	return err
}

func loginUser(username string, hashed_password string) (string, error) {
	var uuid = ""
	err := db.QueryRow("SELECT id FROM users WHERE username = $1 AND password = $2", username, hashed_password).Scan(&uuid);
    return uuid, err
}

func getUser(uuid string) (User, error) {
	var username string
	var ext string
	var id string
	err := db.QueryRow("SELECT username, ext, id FROM users WHERE id = $1", uuid).Scan(&username, &ext, &id);
	user := User{username, id, ext}
    return user, err
}

func setFile(ext string, uuid string) error {
	_, err := db.Exec("UPDATE users SET ext = $1 WHERE id = $2", ext, uuid)
	return err
}

func getFile(uuid string) (string, error){
	var ext = ""
	err := db.QueryRow("SELECT ext FROM users WHERE id = $1", uuid).Scan(&ext);
    return ext, err
}
