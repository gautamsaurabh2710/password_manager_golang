package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	Name              string             `bson:"name,omitempty" json:"name"`
	Email             string             `bson:"email" json:"email"`
	Password          string             `bson:"password" json:"-"`
	OTP               string             `bson:"otp,omitempty" json:"-"`
	OTPExpires        time.Time          `bson:"otpExpires,omitempty" json:"-"`
	ResetToken        string             `bson:"resetToken,omitempty" json:"-"`
	ResetTokenExpires time.Time          `bson:"resetTokenExpires,omitempty" json:"-"`
}

type Password struct {
	ID                primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	UserID            primitive.ObjectID `bson:"userId" json:"userId"`
	Website           string             `bson:"website" json:"website"`
	Username          string             `bson:"username" json:"username"`
	EncryptedPassword string             `bson:"encryptedPassword" json:"-"`
	DecryptedPassword string             `bson:"-" json:"decryptedPassword,omitempty"`
}
