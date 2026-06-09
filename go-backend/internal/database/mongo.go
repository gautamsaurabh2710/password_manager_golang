package database

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DB struct {
	Client    *mongo.Client
	Database  *mongo.Database
	Users     *mongo.Collection
	Passwords *mongo.Collection
}

func Connect(ctx context.Context, uri, databaseName string) (*DB, error) {
	if uri == "" {
		return nil, errors.New("missing MONGO_URI")
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, err
	}

	database := client.Database(databaseName)
	return &DB{
		Client:    client,
		Database:  database,
		Users:     database.Collection("users"),
		Passwords: database.Collection("passwords"),
	}, nil
}
