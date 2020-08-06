package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"time"
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
	refCookie := http.Cookie{Name: "rc", Value: base64.StdEncoding.EncodeToString([]byte(rc)), Secure: false}

	http.SetCookie(writer, &nameCookie)
	http.SetCookie(writer, &authCookie)
	http.SetCookie(writer, &refCookie)
}

func getConnection() *mongo.Collection{
	client, _ := mongo.NewClient(options.Client().ApplyURI("mongodb+srv://user31:1337228@cluster0.tw4ir.mongodb.net/users?retryWrites=true&w=majority\n"))
	client.Connect(context.TODO())
	collection:= client.Database("users").Collection("keys")

	return collection
}

func decodeRefToken(str string) string {
	refKeyDecode, _:=base64.StdEncoding.DecodeString(str)
	refKeyDecodeString:=string(refKeyDecode)

	return refKeyDecodeString
}

func main() {
	http.HandleFunc("/getTokens", func(writer http.ResponseWriter, request *http.Request) {
		user:= request.URL.Query().Get("login")

		tokenString, refKey := generateKeys(user)
		collection:=getConnection()
		p1 := &User{Id: primitive.NewObjectID(), Login: user, AuthKey: tokenString, RefKeys: refKey}
		collection.InsertOne(context.TODO(), p1)
		setCookies(user, tokenString, refKey[0], writer)

		fmt.Fprintf(writer, refKey[0])

	})
	http.HandleFunc("/refresh", func(writer http.ResponseWriter, request *http.Request) {
		login, _ := request.Cookie("username")
		authToken, _ := request.Cookie("ac")
		refToken, _ := request.Cookie("rc")

		collection:=getConnection()

		filter := bson.M{ "login": login.Value }

		var user User
		collection.FindOne(context.TODO(), filter).Decode(&user)
		refKeyDecodeString:=decodeRefToken(refToken.Value)

		if user.AuthKey == authToken.Value && stringInSlice(refKeyDecodeString, user.RefKeys) {
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
	})
	http.HandleFunc("/delToken", func(writer http.ResponseWriter, request *http.Request) {
		token:= request.URL.Query().Get("rc")
		tokenString:=decodeRefToken(token)
		collection:=getConnection()

		collection.UpdateOne(context.TODO(), bson.M{"refkeys" : bson.M{"$eq": tokenString}}, bson.M{"$pull" : bson.M{"refkeys" :  tokenString }})
	})
	http.HandleFunc("/delAllTokens", func(writer http.ResponseWriter, request *http.Request) {
		login:= request.URL.Query().Get("login")
		collection:=getConnection()

		collection.UpdateOne(context.TODO(), bson.M{"login" : login}, bson.M{"$unset" : bson.M{"refkeys" :  "" }})
	})
	http.ListenAndServe(":80", nil)
}