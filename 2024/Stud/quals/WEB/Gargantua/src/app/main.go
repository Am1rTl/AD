package main

import (
    "fmt"
    "net/http"
    "text/template"
    "github.com/google/uuid"
)

type User struct {
    Username string
    Uuid	 string
    Ext		 string
}

var db = establishConnect()

//api handlers
func pProfileHandler(w http.ResponseWriter, r *http.Request) {
    if r.ParseForm() != nil {
        return
    }

    url := r.Form.Get("url")
    uuid := r.Form.Get("uuid")
    if  uuid == "" || url == "" {
    	return
    }

    SaveImage(url, uuid)

    http.Redirect(w, r, "/profile?uuid=" + uuid, http.StatusSeeOther)
}

func pRegisterHandler(w http.ResponseWriter, r *http.Request) {
    if r.ParseForm() != nil {
        return
    }

    username := r.Form.Get("username")
    password := r.Form.Get("password")

    if username == "" || password == "" || password != r.Form.Get("password_repeat") || !isAlphanumeric(username) {
    	return
    }

    hashed_password, err := hashString(password)
    if err != nil {
    	return
    }

    uuid := uuid.New().String()
    if registerUser(uuid, username, hashed_password) != nil {
    	return
    }

    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func pLoginHandler(w http.ResponseWriter, r *http.Request) {
    err := r.ParseForm()
    if err != nil {
        fmt.Printf("Error parsing form: %v\n", err)
        return
    }

    username := r.Form.Get("username")
    hashed_password, err := hashString(r.Form.Get("password"))

    if err != nil {
    	return
    }

    uuid, err := loginUser(username, hashed_password)
    if err != nil {
    	return
    }

    http.Redirect(w, r, "/profile?uuid=" + uuid, http.StatusSeeOther)
}

//template handlers
func gProfileHandler(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFiles("templates/profile.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
	return
    }

    if r.ParseForm() != nil {
        return
    }

    uuid := r.Form.Get("uuid")
    data, err := getUser(uuid)

    err = tmpl.Execute(w, data)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
}

func serveEmptyTemplate(file string, w http.ResponseWriter) {
	tmpl, err := template.ParseFiles(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {}{}
	if err := tmpl.Execute(w, data); err != nil {
    	http.Error(w, err.Error(), http.StatusInternalServerError)
    	return
	}
}

func gLoginHandler(w http.ResponseWriter, r *http.Request) {
	serveEmptyTemplate("templates/login.html", w)
}

func gRegisterHandler(w http.ResponseWriter, r *http.Request) {
	serveEmptyTemplate("templates/register.html", w)
}

func gIndexHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

func main() {
	if db == nil {
		return
	}

    http.HandleFunc("POST /api/upload", pProfileHandler)
    http.HandleFunc("POST /api/login", pLoginHandler)
    http.HandleFunc("POST /api/register", pRegisterHandler)

    http.HandleFunc("GET /profile", gProfileHandler)
    http.HandleFunc("GET /login", gLoginHandler)
    http.HandleFunc("GET /register", gRegisterHandler)
    http.HandleFunc("GET /", gIndexHandler)

    http.ListenAndServe(":3000", nil)
}
