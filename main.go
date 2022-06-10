package main

import (
	"log"
	"net/http"
	"text/template"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template
var Sessions map[string]User
var Users map[string]User

type User struct {
	Username     string
	PasswordHash []byte
}

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	Sessions = make(map[string]User)
	Users = make(map[string]User)
}

func hasSessionCookie(req *http.Request) bool {
	_, err := req.Cookie("_session")
	return err != http.ErrNoCookie
}

func getSessionCookie(req *http.Request) *http.Cookie {
	var sessionCookie *http.Cookie

	if !hasSessionCookie(req) {
		sessionCookie = createNewSessionCookie()
	} else {
		sessionCookie, _ = req.Cookie("_session")
	}
	return sessionCookie
}

func loggedIn(sessionCookie *http.Cookie) bool {
	_, ok := Sessions[sessionCookie.Value]
	return ok
}

func createNewSessionCookie() *http.Cookie {
	id := uuid.NewV4()
	c := &http.Cookie{
		Name:  "_session",
		Value: id.String(),
	}
	return c
}

func root(res http.ResponseWriter, req *http.Request) {
	var context User

	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)

	if !loggedIn(sessionCookie) {
		http.SetCookie(res, sessionCookie)
		context = User{Username: "Guest"}
	} else {
		context = Sessions[sessionCookie.Value]
	}

	tpl.ExecuteTemplate(res, "index.html", context)
}

func signup(res http.ResponseWriter, req *http.Request) {
	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)

	if loggedIn(sessionCookie) {
		http.Redirect(res, req, "/bar", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Panic(err)
		}
		_, exists := Users[username]
		if exists {
			msg := "Username already exists"
			tpl.ExecuteTemplate(res, "signup.html", msg)
			return
		}
		Users[username] = User{Username: username, PasswordHash: hash}
		http.Redirect(res, req, "/login", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "signup.html", nil)
}

func bar(res http.ResponseWriter, req *http.Request) {
	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)

	if !loggedIn(sessionCookie) {
		http.Redirect(res, req, "/signup", http.StatusSeeOther)
	}
	user := Sessions[sessionCookie.Value]
	tpl.ExecuteTemplate(res, "bar.html", user)
}

func login(res http.ResponseWriter, req *http.Request) {
	sessionCookie := getSessionCookie(req)
	http.SetCookie(res, sessionCookie)

	if loggedIn(sessionCookie) {
		http.Redirect(res, req, "/bar", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")

		user, ok := Users[username]
		if !ok {
			msg := "User not found"
			tpl.ExecuteTemplate(res, "login.html", msg)
			return
		}
		err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password))
		if err != nil {
			msg := "Wrong password"
			tpl.ExecuteTemplate(res, "login.html", msg)
			return
		}
		Sessions[sessionCookie.Value] = user
		http.Redirect(res, req, "/bar", http.StatusSeeOther)
		return
	}
	msg := "Login please"
	tpl.ExecuteTemplate(res, "login.html", msg)
}

func logout(res http.ResponseWriter, req *http.Request) {
	sessionCookie := getSessionCookie(req)
	sessionCookie.MaxAge = -1
	http.SetCookie(res, sessionCookie)
	http.Redirect(res, req, "/", http.StatusSeeOther)
}

func main() {
	http.HandleFunc("/", root)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/bar", bar)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe("localhost:8000", nil)
}
