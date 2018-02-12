package models

import "gopkg.in/mgo.v2/bson"

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Represents a movie, we uses bson keyword to tell the mgo driver how to name
// the properties in mongodb document
type User struct {
	ID          bson.ObjectId 	`bson:"_id" json:"id"`
	Username        string        	`bson:"username" json:"username"`
//	Email  		string        	`bson:"email" json:"email"`
	Password 	string        	`bson:"password" json:"password"`
}

