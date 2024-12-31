package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	// "github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v5"
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
	Email    string             `json: email`
	Password string             `json: password`
	FullName string             `json: fullname`
	Refresh  string             `json: refresh,omitempty`
}

type Login struct {
	Email    string `json: email`
	Password string `json: password`
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

	// app.Use(cors.New(cors.Config{
	// 	AllowCredentials: true,
	// }))

	app.Get("/api/", me)
	app.Post("/api/login", login)
	app.Post("/api/register", register)
	app.Post("/api/logout", logout)
	app.Post("/api/refresh", refresh)

	port := os.Getenv("PORT")

	if port == "" {
		port = "5000"
	}

	log.Fatal(app.Listen("0.0.0.0:" + port))

}
func me(c *fiber.Ctx) error {
	return c.Status(200).JSON(fiber.Map{"message": "Hello, World!"})
}

func login(c *fiber.Ctx) error {

	login := new(Login)

	if err := c.BodyParser(login); err != nil {
		return err
	}

	// Các thông tin không được để trống
	requiredFields := map[string]string{
		"Email":    login.Email,
		"Mật khẩu": login.Password,
	}

	for field, value := range requiredFields {
		if value == "" {
			return c.Status(404).JSON(fiber.Map{"error": field + " không được để trống"})
		}
	}

	// Kiểm tra email có tồn tại không
	var existUser Users
	err := collection.FindOne(context.Background(), bson.M{"email": login.Email}).Decode(&existUser)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Email chưa được đăng ký!!!"})
	}

	// Kiểm tra password có đúng không
	err = bcrypt.CompareHashAndPassword([]byte(existUser.Password), []byte(login.Password))
	if err != nil {
		return c.Status(401).JSON(fiber.Map{"error": "Thông tin tài khoản không đúng!!!"})
	}

	// Tạo access token
	claimsAccess := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    existUser.ID.Hex(),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 12)), // 12h
	})

	accesstoken, err := claimsAccess.SignedString([]byte(os.Getenv("SECRET_ACCESS_KEY")))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Không thể tạo access token"})
	}

	claimsRefresh := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    existUser.ID.Hex(),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 7)), // 7d
	})

	refreshtoken, err := claimsRefresh.SignedString([]byte(os.Getenv("SECRET_REFRESH_KEY")))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Không thể tạo refresh token"})
	}

	// Lưu refresh token vào cơ sở dữ liệu
	update := bson.M{"$set": bson.M{"refresh": refreshtoken}}
	_, err = collection.UpdateOne(context.Background(), bson.M{"_id": existUser.ID}, update)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Không thể lưu refresh token"})
	}

	return c.Status(200).JSON(fiber.Map{
		"message": "Đăng nhập thành công",
		"data": map[string]interface{}{
			"id":       existUser.ID,
			"email":    existUser.Email,
			"fullname": existUser.FullName,
		},
		"token": accesstoken})
	// return c.Status(200).JSON(fiber.Map{"message": "Login Success"})
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
	var existUser Users
	err := collection.FindOne(context.Background(), bson.M{"email": user.Email}).Decode(&existUser)
	if err == nil {
		return c.Status(404).JSON(fiber.Map{"error": "Email đã được đăng ký!!!"})
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

	return c.Status(201).JSON(fiber.Map{
		"message": "Đăng ký thành công",
		"data": map[string]interface{}{
			"id":       user.ID,
			"email":    user.Email,
			"fullname": user.FullName,
		},
	})

}

func logout(c *fiber.Ctx) error {
	return c.Status(200).JSON(fiber.Map{"message": "Logout Success"})
}

func refresh(c *fiber.Ctx) error {
	return c.Status(200).JSON(fiber.Map{"message": "Refresh Success"})
}
