package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var collection *mongo.Collection

type Users struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Email    string             `json: "email"`
	Password string             `json: password`
	FullName string             `json: fullname`
}

func main() {

	fmt.Println("JWT Token Authentication")

	if os.Getenv("ENV") != "production" {
		err := godotenv.Load(".env")
		if err != nil {
			log.Fatal("Error loading .env file", err)
		}
	}

	MONGODB_URL := os.Getenv("MONGODB_URI")

	fmt.Println("MONGODB_URL: ", MONGODB_URL)

	clientOptions := options.Client().ApplyURI(MONGODB_URL)
	client, err := mongo.Connect(context.Background(), clientOptions)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connect to database mongodb atlas")

	collection = client.Database("jwt_golang").Collection("users")

	log.Println(collection)

	app := fiber.New()

	app.Get("/api/", me)
	app.Post("/api/login", login)
	app.Post("/api/register", register)
	app.Post("/api/logout", logout)
	app.Post("/api/refresh", refresh)

	port := os.Getenv("PORT")

	if port == "" {
		port = "5000"
	}

	if os.Getenv("ENV") == "production" {
		app.Static("/", "./client/dist")
	}

	log.Fatal(app.Listen("0.0.0.0:" + port))

}
func me(c *fiber.Ctx) error {
	return c.Status(200).JSON(fiber.Map{"message": "Hello, World!"})
}

func login(c *fiber.Ctx) error {
	return c.Status(200).JSON(fiber.Map{"message": "Login Success"})
}

func register(c *fiber.Ctx) error {
	user := new(Users)

	if err := c.BodyParser(user); err != nil {
		return err
	}

	// Các thông tin không được để trống
	requiredFields := map[string]string{
		"Email":    user.Email,
		"Mật khẩu": user.Password,
		"Họ tên":   user.FullName,
	}

	for field, value := range requiredFields {
		if value == "" {
			return c.Status(404).JSON(fiber.Map{"error": field + " không được để trống"})
		}
	}

	// Kiểm tra đã có người đăng ký chưa
	count, err := collection.CountDocuments(context.Background(), bson.M{"email": user.Email})
	if err != nil {
		return err
	}

	if count > 0 {
		return c.Status(400).JSON(fiber.Map{"error": "Email đã có người đăng ký!!!"})
	}

	// Mã hóa mật khẩu trước khi lưu vào cơ sở dữ liệu
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Lỗi khi ma hóa mật khẩu"})
	}
	user.Password = string(hashedPassword)

	registerResult, err := collection.InsertOne(context.Background(), user)
	if err != nil {
		return err
	}

	user.ID = registerResult.InsertedID.(primitive.ObjectID)

	return c.Status(201).JSON(user)

}

func logout(c *fiber.Ctx) error {
	return c.Status(200).JSON(fiber.Map{"message": "Logout Success"})
}

func refresh(c *fiber.Ctx) error {
	return c.Status(200).JSON(fiber.Map{"message": "Refresh Success"})
}
