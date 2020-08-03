package main

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"

	//"gopkg.in/mgo.v2/bson"

	//"go.mongodb.org/mongo-driver/mongo/readpref"
	"net/http"
	"os"
	//"net/http"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id 		primitive.ObjectID 	`bson:"_id"`
	Login 	string			`bson:login`
	AuthKey string 			`bson:authKey`
	RefKeys []string 		`bson:refKeys`
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func generateKeys(user string) (string, []string){
	token:= jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{ "Login": user, "Key":  time.Now().Unix()})
	tokenString, _:= token.SignedString([]byte(os.Getenv("KEY")))
	key, _ := bcrypt.GenerateFromPassword([]byte(tokenString), 4)

	strings := []string{string(key)}

	return tokenString, strings
}

func setCookies(user, ac, rc string, writer http.ResponseWriter){
	nameCookie := http.Cookie{Name: "username", Value: user, Secure: false}
	authCookie := http.Cookie{Name: "ac", Value: ac, Secure: false}
	refCookie := http.Cookie{Name: "rc", Value: rc, Secure: false}

	http.SetCookie(writer, &nameCookie)
	http.SetCookie(writer, &authCookie)
	http.SetCookie(writer, &refCookie)
}

func main() {
	http.HandleFunc("/getTokens", func(writer http.ResponseWriter, request *http.Request) {
		user:= request.URL.Query().Get("login")

		token:= jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{ "Login": user, "Key":  time.Now().Unix()})
		tokenString, _:= token.SignedString([]byte(os.Getenv("KEY")))
		key, _ := bcrypt.GenerateFromPassword([]byte(tokenString), 4)

		client, _ := mongo.NewClient(options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
		client.Connect(context.TODO())
		collection:= client.Database("users").Collection("keys")

		strings := []string{string(key)}
		p1 := &User{Id: primitive.NewObjectID(), Login: user, AuthKey: tokenString, RefKeys: strings}

		collection.InsertOne(context.TODO(), p1)

		nameCookie := http.Cookie{Name: "username", Value: user, Secure: false}
		authCookie := http.Cookie{Name: "ac", Value: tokenString, Secure: false}
		refCookie := http.Cookie{Name: "rc", Value: string(key), Secure: false}

		http.SetCookie(writer, &nameCookie)
		http.SetCookie(writer, &authCookie)
		http.SetCookie(writer, &refCookie)

		fmt.Fprintf(writer, string(key))

	})
	http.HandleFunc("/refresh", func(writer http.ResponseWriter, request *http.Request) {
		login, _ := request.Cookie("username")
		authToken, _ := request.Cookie("ac")
		refToken, _ := request.Cookie("rc")

		client, _ := mongo.NewClient(options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
		client.Connect(context.TODO())
		collection:= client.Database("users").Collection("keys")

		filter := bson.M{ "login": login.Value } // , bson.M{ "$in": []string {refToken.Value} } , "authKey": authToken.Value

		var user User
		collection.FindOne(context.TODO(), filter).Decode(&user)

		if user.AuthKey == authToken.Value && stringInSlice(refToken.Value, user.RefKeys) {
			at, rt := generateKeys(login.Value)
			collection.UpdateOne(context.TODO(), bson.M{ "login": login.Value }, bson.M{"$set": bson.M{"authkey": at, "refkeys": rt}})
			setCookies(login.Value, at, rt[0], writer)
			fmt.Fprintf(writer, "Ключи изменены!" + "\n")
			/*
			fmt.Fprintf(writer, user.AuthKey + "\n")
			fmt.Fprintf(writer, authToken.Value + "\n")
			fmt.Fprintf(writer, user.RefKeys[0] + "\n")
			fmt.Fprintf(writer, refToken.Value + "\n")
			*/

		} else {
			fmt.Fprintf(writer, "Такого пользователя нет!")
		}

		//fmt.Fprintf(writer, user.Login)
	})
	http.HandleFunc("/delToken", func(writer http.ResponseWriter, request *http.Request) {
		tokenString:= request.URL.Query().Get("rc")
		client, _ := mongo.NewClient(options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
		client.Connect(context.TODO())
		collection:= client.Database("users").Collection("keys")

		collection.UpdateOne(context.TODO(), bson.M{"refkeys" : bson.M{"$eq": tokenString}}, bson.M{"$pull" : bson.M{"refkeys" :  tokenString }})
		//fmt.Fprint(writer, int(res.ModifiedCount), err)res,err:=
	})
	http.HandleFunc("/delAllTokens", func(writer http.ResponseWriter, request *http.Request) {
		login:= request.URL.Query().Get("login")
		client, _ := mongo.NewClient(options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
		client.Connect(context.TODO())
		collection:= client.Database("users").Collection("keys")

		collection.UpdateOne(context.TODO(), bson.M{"login" : login}, bson.M{"$unset" : bson.M{"refkeys" :  "" }})
	})
	http.ListenAndServe(":80", nil)
	/*
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		cookie := http.Cookie{Name: "username", Value: "astaxie", Secure: false}
		http.SetCookie(writer, &cookie)
		cookie1, _ := request.Cookie("username")
		fmt.Fprint(writer, cookie1)
	})
	http.ListenAndServe(":80", nil)
	*/
	token:= jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{ "Hell": "No",
																		"No": "Hell",})
	tokenString, err:= token.SignedString([]byte(os.Getenv("1337")))
	fmt.Println(tokenString, err)

	result, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error){ return []byte(os.Getenv("1337")), nil})
	claims := result.Claims.(jwt.MapClaims)
	fmt.Println(claims["Hell"])
}

