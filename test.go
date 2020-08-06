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
	"strconv"
	"time"
)

type Keys struct {
	AuthKey	string `bson:authkey`
	RefKey string `bson:refkey`
}

type User struct {
	Id 		primitive.ObjectID 	`bson:"_id"`
	Login 	string			`bson:login`
	Keys 	[]Keys			`bson:keys`
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func generateKeys(user string, userKey int64) (string, []string){
	token:= jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{ "Login": user, "Key": strconv.FormatInt(userKey, 10) })
	tokenString, _:= token.SignedString([]byte(os.Getenv("KEY")))
	key, _ := bcrypt.GenerateFromPassword([]byte(tokenString), 4)

	strings := []string{string(key)}

	return tokenString, strings
}

func setCookies(ac, rc string, writer http.ResponseWriter){
	authCookie := http.Cookie{Name: "ac", Value: ac, Secure: false}
	refCookie := http.Cookie{Name: "rc", Value: base64.StdEncoding.EncodeToString([]byte(rc)), Secure: false}

	http.SetCookie(writer, &authCookie)
	http.SetCookie(writer, &refCookie)
}

func getConnection() (*mongo.Collection, *mongo.Session){
	client, _ := mongo.NewClient(options.Client().ApplyURI("mongodb+srv://user31:1337228@cluster0.tw4ir.mongodb.net/users?retryWrites=true&w=majority"))
	client.Connect(context.TODO())
	collection:= client.Database("users").Collection("keys")
	session, _:= client.StartSession()

	return collection, &session
}

func decodeRefToken(str string) string {
	refKeyDecode, _:=base64.StdEncoding.DecodeString(str)
	refKeyDecodeString:=string(refKeyDecode)

	return refKeyDecodeString
}

func decodeAuthToken(str string) jwt.MapClaims {
	token, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("KEY")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims
	} else {
		fmt.Println(err)
	}
	return nil
}

func main() {
	http.HandleFunc("/getTokens", func(writer http.ResponseWriter, request *http.Request) {
		user:= request.URL.Query().Get("login")

		authKey:=time.Now().Unix()
		tokenString, refKey := generateKeys(user, authKey)
		collection, session:=getConnection()

		var userStruct User
		collection.FindOne(context.TODO(), bson.M{"login" : user}).Decode(&userStruct)

		mongo.WithSession(context.TODO(), *session, func(sc mongo.SessionContext) error {
			if userStruct.Login == user{
				collection.UpdateOne(context.TODO(), bson.M{ "login": user }, bson.M{"$push": bson.M{"keys": bson.M{"authkey" : strconv.FormatInt(authKey, 10), "refkey": refKey[0]}}})
			}else {
				p1 := &User{Id: primitive.NewObjectID(), Login: user, Keys: []Keys{Keys{strconv.FormatInt(authKey, 10), refKey[0]}}}
				collection.InsertOne(context.TODO(), p1)
			}

			return nil
		})
		(*session).EndSession(context.TODO())


		setCookies(tokenString, refKey[0], writer)
		fmt.Fprintf(writer, refKey[0])

	})
	http.HandleFunc("/refresh", func(writer http.ResponseWriter, request *http.Request) {
		authToken, _ := request.Cookie("ac")
		refToken, _ := request.Cookie("rc")

		collection, session:=getConnection()

		authData:=decodeAuthToken(authToken.Value)
		login:=authData["Login"].(string)
		var user User
		collection.FindOne(context.TODO(), bson.M{ "login": login, "keys" : bson.M{"$elemMatch" : bson.M {"authkey" : authData["Key"], "refkey" : decodeRefToken(refToken.Value)}}}).Decode(&user)

		if user.Login == login{
			authKey:=time.Now().Unix()
			at, rt := generateKeys(login, authKey)
			mongo.WithSession(context.TODO(), *session, func(sc mongo.SessionContext) error {
				collection.UpdateOne(context.TODO(), bson.M{ "login": login }, bson.M{"$pull": bson.M{"keys": bson.M{"authkey" : authData["Key"], "refkey" : decodeRefToken(refToken.Value)}}})
				collection.UpdateOne(context.TODO(), bson.M{ "login": login }, bson.M{"$push": bson.M{"keys" : bson.M{"authkey": strconv.FormatInt(authKey,10), "refkey": rt[0]}}})
				return nil
			})
			(*session).EndSession(context.TODO())
			setCookies(at, rt[0], writer)
			fmt.Fprintf(writer, "Ключи изменены!" + "\n")
		}


	})
	http.HandleFunc("/delToken", func(writer http.ResponseWriter, request *http.Request) {
		token:= request.URL.Query().Get("rc")
		decodeFlag:= request.URL.Query().Get("decode")

		var tokenString string

		if decodeFlag == "true" {
			tokenString=decodeRefToken(token)
		}else {
			tokenString = token
		}

		collection, session:=getConnection()

		mongo.WithSession(context.TODO(), *session, func(sc mongo.SessionContext) error {
			collection.UpdateOne(context.TODO(), bson.M{"keys" : bson.M{"$elemMatch" : bson.M{"refkey" : tokenString}}}, bson.M{"$unset" :  bson.M{"keys.$.refkey" : "" }})
			return nil
		})
		(*session).EndSession(context.TODO())
	})
	http.HandleFunc("/delAllTokens", func(writer http.ResponseWriter, request *http.Request) {
		login:= request.URL.Query().Get("login")
		collection, session:=getConnection()

		mongo.WithSession(context.TODO(), *session, func(sc mongo.SessionContext) error {
			collection.UpdateMany(context.TODO(), bson.M{"login" : login}, bson.M{"$unset" :  bson.M{"keys.$[].refkey" : "" }})
			return nil
		})
		(*session).EndSession(context.TODO())
	})
	http.ListenAndServe(":" + os.Getenv("PORT"), nil)
}