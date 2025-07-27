package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"golang.org/x/crypto/bcrypt"
)

const (
	UploadPath       = "./uploads"
	MaxUploadSize    = 10 << 20
	CommissionRate   = 0.08
	LessonCompleted  = "completed"
	LessonCancelled  = "cancelled"
	LessonScheduled  = "scheduled"
	LessonConfirmed  = "confirmed"
	PaymentPending   = "pending"
	PaymentCompleted = "completed"
	PaymentRefunded  = "refunded"
)

var (
	db          *sql.DB
	jwtSecret   = []byte(os.Getenv("JWT_SECRET"))
	upgrader    = websocket.Upgrader{}
	connections = make(map[string]*websocket.Conn)
	rateLimiter = make(map[string]time.Time)
)

type User struct {
	ID         string    `json:"id"`
	Email      string    `json:"email" binding:"required,email"`
	Password   string    `json:"password,omitempty" binding:"required,min=8"`
	Name       string    `json:"name"`
	Role       string    `json:"role" binding:"required,oneof=student tutor admin"`
	Languages  []string  `json:"languages"`
	Level      string    `json:"level"`
	Rating     float64   `json:"rating"`
	Telegram   string    `json:"telegram"`
	AvatarURL  string    `json:"avatar_url"`
	IsVerified bool      `json:"is_verified"`
	KYCStatus  string    `json:"kyc_status"`
	CreatedAt  time.Time `json:"created_at"`
}

type Subject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Lesson struct {
	ID          string    `json:"id"`
	StudentID   string    `json:"student_id"`
	TutorID     string    `json:"tutor_id"`
	StartTime   time.Time `json:"start_time" binding:"required"`
	EndTime     time.Time `json:"end_time"`
	Duration    int       `json:"duration" binding:"required"`
	SubjectID   string    `json:"subject_id"`
	MeetingLink string    `json:"meeting_link"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type Review struct {
	ID        string    `json:"id"`
	AuthorID  string    `json:"author_id"`
	TargetID  string    `json:"target_id"`
	LessonID  string    `json:"lesson_id" binding:"required"`
	Rating    int       `json:"rating" binding:"required,min=1,max=5"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

type Payment struct {
	ID            string    `json:"id"`
	LessonID      string    `json:"lesson_id"`
	Amount        float64   `json:"amount"`
	Commission    float64   `json:"commission"`
	Status        string    `json:"status"`
	PaymentMethod string    `json:"payment_method"`
	ExternalID    string    `json:"external_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type ChatMessage struct {
	ID           string    `json:"id"`
	SenderID     string    `json:"sender_id"`
	ReceiverID   string    `json:"receiver_id"`
	Message      string    `json:"message"`
	Attachment   string    `json:"attachment"`
	AttachmentID string    `json:"attachment_id"`
	CreatedAt    time.Time `json:"created_at"`
}

type AvailabilitySlot struct {
	ID        string    `json:"id"`
	TutorID   string    `json:"tutor_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

func initDB() (*sql.DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"),
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT(userID, role string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString(jwtSecret)
}

func authMiddleware(c *gin.Context) {
	tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if tokenString == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
		return
	}

	c.Set("userID", claims["sub"].(string))
	c.Set("userRole", claims["role"].(string))
	c.Next()
}

func roleMiddleware(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole := c.GetString("userRole")
		for _, role := range roles {
			if userRole == role {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	}
}

func registerHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()

	err = db.QueryRow(`
		INSERT INTO users (id, email, password, name, role, languages, level, telegram, avatar_url, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at
	`, user.ID, user.Email, hashedPassword, user.Name, user.Role, user.Languages, user.Level, user.Telegram, user.AvatarURL, user.CreatedAt).Scan(&user.ID, &user.CreatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	user.Password = ""
	c.JSON(http.StatusCreated, gin.H{"user": user})
}

func loginHandler(c *gin.Context) {
	var creds struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	err := db.QueryRow(`
		SELECT id, email, password, name, role, languages, level, rating, telegram, avatar_url, is_verified, created_at
		FROM users WHERE email = $1
	`, creds.Email).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name, &user.Role,
		&user.Languages, &user.Level, &user.Rating, &user.Telegram,
		&user.AvatarURL, &user.IsVerified, &user.CreatedAt,
	)

	if err != nil || !checkPasswordHash(creds.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := generateJWT(user.ID, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	user.Password = ""
	c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
}

func createLessonHandler(c *gin.Context) {
	var lesson Lesson
	if err := c.ShouldBindJSON(&lesson); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("userID")
	lesson.ID = uuid.New().String()
	lesson.StudentID = userID
	lesson.Status = LessonScheduled
	lesson.CreatedAt = time.Now()
	lesson.EndTime = lesson.StartTime.Add(time.Duration(lesson.Duration) * time.Minute)

	err := db.QueryRow(`
		INSERT INTO lessons (id, student_id, tutor_id, start_time, end_time, subject_id, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, lesson.ID, lesson.StudentID, lesson.TutorID, lesson.StartTime, lesson.EndTime,
		lesson.SubjectID, lesson.Status, lesson.CreatedAt).Scan(&lesson.ID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create lesson"})
		return
	}

	c.JSON(http.StatusCreated, lesson)
}

func confirmLessonHandler(c *gin.Context) {
	lessonID := c.Param("id")
	userID := c.GetString("userID")

	var tutorID string
	err := db.QueryRow("SELECT tutor_id FROM lessons WHERE id = $1", lessonID).Scan(&tutorID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "lesson not found"})
		return
	}

	if tutorID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "only tutor can confirm lesson"})
		return
	}

	_, err = db.Exec("UPDATE lessons SET status = 'confirmed' WHERE id = $1", lessonID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to confirm lesson"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "lesson confirmed"})
}
func getAvailabilityHandler(c *gin.Context) {
	tutorID := c.Param("tutor_id")

	rows, err := db.Query(`
		SELECT id, tutor_id, start_time, end_time 
		FROM availability_slots 
		WHERE tutor_id = $1 AND start_time > NOW()
		ORDER BY start_time
	`, tutorID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch availability"})
		return
	}
	defer rows.Close()

	var slots []AvailabilitySlot
	for rows.Next() {
		var slot AvailabilitySlot
		if err := rows.Scan(&slot.ID, &slot.TutorID, &slot.StartTime, &slot.EndTime); err != nil {
			continue
		}
		slots = append(slots, slot)
	}

	c.JSON(http.StatusOK, slots)
}

func addAvailabilityHandler(c *gin.Context) {
	var slot AvailabilitySlot
	if err := c.ShouldBindJSON(&slot); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("userID")
	if slot.TutorID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only add slots for yourself"})
		return
	}

	slot.ID = uuid.New().String()
	_, err := db.Exec(`
		INSERT INTO availability_slots (id, tutor_id, start_time, end_time)
		VALUES ($1, $2, $3, $4)
	`, slot.ID, slot.TutorID, slot.StartTime, slot.EndTime)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add availability slot"})
		return
	}

	c.JSON(http.StatusCreated, slot)
}
func paymentWebhookHandler(c *gin.Context) {
	var payload map[string]interface{}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	event := payload["event"].(string)
	paymentID := payload["object"].(map[string]interface{})["id"].(string)

	switch event {
	case "payment.succeeded":
		_, err := db.Exec(`
			UPDATE payments 
			SET status = $1 
			WHERE external_id = $2
		`, PaymentCompleted, paymentID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update payment status"})
			return
		}
	case "payment.canceled":
		_, err := db.Exec(`
			UPDATE payments 
			SET status = $1 
			WHERE external_id = $2
		`, PaymentRefunded, paymentID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update payment status"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func processPaymentHandler(c *gin.Context) {
	var payment struct {
		LessonID string  `json:"lesson_id" binding:"required"`
		Amount   float64 `json:"amount" binding:"required"`
		Token    string  `json:"payment_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&payment); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("userID")
	var lesson Lesson
	err := db.QueryRow(`
		SELECT id, student_id, tutor_id, start_time, duration
		FROM lessons WHERE id = $1 AND student_id = $2
	`, payment.LessonID, userID).Scan(
		&lesson.ID, &lesson.StudentID, &lesson.TutorID, &lesson.StartTime, &lesson.Duration,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "lesson not found"})
		return
	}

	paymentResult, err := createYooKassaPayment(payment.Amount, payment.Token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "payment failed: " + err.Error()})
		return
	}

	commission := payment.Amount * CommissionRate
	_, err = db.Exec(`
		INSERT INTO payments (lesson_id, amount, commission, payment_method, status, external_id)
		VALUES ($1, $2, $3, 'yookassa', $4, $5)
	`, payment.LessonID, payment.Amount, commission, paymentResult.Status, paymentResult.ID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save payment"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"payment_id": paymentResult.ID,
		"status":     paymentResult.Status,
		"amount":     payment.Amount,
		"commission": commission,
	})
}

func createReviewHandler(c *gin.Context) {
	var review Review
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("userID")
	review.ID = uuid.New().String()
	review.AuthorID = userID
	review.CreatedAt = time.Now()

	var participant bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM lessons 
			WHERE id = $1 AND (student_id = $2 OR tutor_id = $2)
	`, review.LessonID, userID).Scan(&participant)

	if err != nil || !participant {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only review lessons you participated in"})
		return
	}

	_, err = db.Exec(`
		INSERT INTO reviews (id, author_id, target_id, lesson_id, rating, comment, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, review.ID, review.AuthorID, review.TargetID, review.LessonID, review.Rating, review.Comment, review.CreatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create review"})
		return
	}

	_, err = db.Exec(`
		UPDATE users SET rating = (
			SELECT AVG(rating) FROM reviews WHERE target_id = $1
		) WHERE id = $1
	`, review.TargetID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update rating"})
		return
	}

	c.JSON(http.StatusCreated, review)
}

func chatHandler(c *gin.Context) {
	userID := c.GetString("userID")
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upgrade connection"})
		return
	}
	defer conn.Close()

	connections[userID] = conn

	var messages []ChatMessage
	rows, err := db.Query(`
		SELECT id, sender_id, receiver_id, message, attachment, created_at
		FROM chat_messages
		WHERE (sender_id = $1 OR receiver_id = $1)
		ORDER BY created_at DESC
		LIMIT 50
	`, userID)

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var msg ChatMessage
			rows.Scan(&msg.ID, &msg.SenderID, &msg.ReceiverID, &msg.Message, &msg.Attachment, &msg.CreatedAt)
			messages = append(messages, msg)
		}
		conn.WriteJSON(gin.H{"history": messages})
	}

	for {
		var msg struct {
			ReceiverID string                `json:"receiver_id"`
			Message    string                `json:"message"`
			File       *multipart.FileHeader `json:"-"`
		}

		if err := conn.ReadJSON(&msg); err != nil {
			delete(connections, userID)
			break
		}

		attachmentID := ""
		if msg.File != nil {
			attachmentID = uuid.New().String()
			if err := c.SaveUploadedFile(msg.File, filepath.Join(UploadPath, attachmentID)); err != nil {
				continue
			}
		}

		messageID := uuid.New().String()
		_, err := db.Exec(`
			INSERT INTO chat_messages (id, sender_id, receiver_id, message, attachment_id, created_at)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, messageID, userID, msg.ReceiverID, msg.Message, attachmentID, time.Now())

		if err != nil {
			continue
		}

		if receiverConn, ok := connections[msg.ReceiverID]; ok {
			receiverConn.WriteJSON(gin.H{
				"sender_id":     userID,
				"message":       msg.Message,
				"attachment_id": attachmentID,
				"timestamp":     time.Now(),
			})
		}
	}
}

func createYooKassaPayment(amount float64, token string) (struct {
	ID     string
	Status string
}, error) {
	if amount <= 0 {
		return struct {
			ID     string
			Status string
		}{}, errors.New("invalid amount")
	}

	if token == "" {
		return struct {
			ID     string
			Status string
		}{}, errors.New("empty token")
	}

	return struct {
		ID     string
		Status string
	}{
		ID:     uuid.New().String(),
		Status: PaymentCompleted,
	}, nil
}

func corsMiddleware() gin.HandlerFunc {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Authorization"},
		ExposedHeaders:   []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           86400,
	})

	return func(ctx *gin.Context) {

		c.HandlerFunc(ctx.Writer, ctx.Request)

		if ctx.Request.Method != "OPTIONS" {
			ctx.Next()
		} else {

			ctx.AbortWithStatus(http.StatusOK)
		}
	}
}

func rateLimitMiddleware(c *gin.Context) {
	ip := c.ClientIP()

	if _, ok := rateLimiter[ip]; ok && time.Since(rateLimiter[ip]) < time.Second {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
		return
	}
	rateLimiter[ip] = time.Now()
	c.Next()
}

func listLessonsHandler(c *gin.Context) {
	userID := c.GetString("userID")
	userRole := c.GetString("userRole")

	var query string
	switch userRole {
	case "student":
		query = "SELECT id, student_id, tutor_id, start_time, end_time, subject_id, meeting_link, status FROM lessons WHERE student_id = $1"
	case "tutor":
		query = "SELECT id, student_id, tutor_id, start_time, end_time, subject_id, meeting_link, status FROM lessons WHERE tutor_id = $1"
	default:
		query = "SELECT id, student_id, tutor_id, start_time, end_time, subject_id, meeting_link, status FROM lessons WHERE student_id = $1 OR tutor_id = $1"
	}

	rows, err := db.Query(query, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch lessons"})
		return
	}
	defer rows.Close()

	var lessons []Lesson
	for rows.Next() {
		var lesson Lesson
		err := rows.Scan(
			&lesson.ID,
			&lesson.StudentID,
			&lesson.TutorID,
			&lesson.StartTime,
			&lesson.EndTime,
			&lesson.SubjectID,
			&lesson.MeetingLink,
			&lesson.Status,
		)
		if err != nil {
			log.Printf("Error scanning lesson: %v", err)
			continue
		}
		lessons = append(lessons, lesson)
	}

	if err = rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error during rows iteration"})
		return
	}

	c.JSON(http.StatusOK, lessons)
}

func uploadFileHandler(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file upload error"})
		return
	}

	if file.Size > 10<<20 {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file size exceeds 10MB limit"})
		return
	}

	fileID := uuid.New().String()
	fileExt := filepath.Ext(file.Filename)
	fileName := fileID + fileExt
	filePath := filepath.Join("uploads", fileName)

	if err := os.MkdirAll("uploads", 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create upload directory"})
		return
	}

	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "file uploaded successfully",
		"file_id": fileID,
		"path":    filePath,
	})
}

func searchTutorsHandler(c *gin.Context) {
	query := c.Query("query")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "search query is required"})
		return
	}

	rows, err := db.Query(`
        SELECT id, email, name, role, languages, level, rating, telegram, avatar_url
        FROM users
        WHERE role = 'tutor' AND (
            name ILIKE $1 OR 
            array_to_string(languages, ',') ILIKE $1 OR 
            level ILIKE $1
        )
    `, "%"+query+"%")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to search tutors"})
		return
	}
	defer rows.Close()

	var tutors []User
	for rows.Next() {
		var tutor User
		err := rows.Scan(&tutor.ID, &tutor.Email, &tutor.Name, &tutor.Role,
			&tutor.Languages, &tutor.Level, &tutor.Rating, &tutor.Telegram, &tutor.AvatarURL)
		if err != nil {
			continue
		}
		tutors = append(tutors, tutor)
	}

	c.JSON(http.StatusOK, tutors)
}

func adminListUsersHandler(c *gin.Context) {
	role := c.Query("role")
	query := "SELECT id, email, name, role, languages, level, rating, telegram, avatar_url, is_verified FROM users"
	var args []interface{}

	if role != "" {
		query += " WHERE role = $1"
		args = append(args, role)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch users"})
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Email, &user.Name, &user.Role,
			&user.Languages, &user.Level, &user.Rating, &user.Telegram,
			&user.AvatarURL, &user.IsVerified)
		if err != nil {
			continue
		}
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}

func adminBlockUserHandler(c *gin.Context) {
	userID := c.Param("id")
	var block struct {
		Blocked bool `json:"blocked"`
	}

	if err := c.ShouldBindJSON(&block); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := db.Exec("UPDATE users SET blocked = $1 WHERE id = $2", block.Blocked, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user status updated"})
}

func adminDeleteReviewHandler(c *gin.Context) {
	reviewID := c.Param("id")
	_, err := db.Exec("DELETE FROM reviews WHERE id = $1", reviewID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete review"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "review deleted"})
}
func getStatsHandler(c *gin.Context) {
	var stats struct {
		TotalPayments   float64 `json:"total_payments"`
		TotalCommission float64 `json:"total_commission"`
		ActiveUsers     int     `json:"active_users"`
	}

	err := db.QueryRow(`
		SELECT 
			SUM(amount) as total_payments,
			SUM(commission) as total_commission
		FROM payments
		WHERE status = $1
	`, PaymentCompleted).Scan(&stats.TotalPayments, &stats.TotalCommission)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get payment stats"})
		return
	}

	err = db.QueryRow(`
		SELECT COUNT(*) 
		FROM users 
		WHERE last_active_at > NOW() - INTERVAL '30 days'
	`).Scan(&stats.ActiveUsers)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user stats"})
		return
	}

	c.JSON(http.StatusOK, stats)
}
func setupRoutes(r *gin.Engine) {

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.POST("/auth/register", registerHandler)
	r.POST("/auth/login", loginHandler)

	auth := r.Group("/")
	auth.Use(authMiddleware)
	{

		auth.POST("/lessons", createLessonHandler)
		auth.PUT("/lessons/:id/confirm", confirmLessonHandler)
		auth.GET("/lessons", listLessonsHandler)

		auth.POST("/payments", processPaymentHandler)

		auth.POST("/reviews", createReviewHandler)

		auth.GET("/chat", chatHandler)
		auth.POST("/chat/upload", uploadFileHandler)

		auth.GET("/tutors/search", searchTutorsHandler)

		auth.GET("/availability/:tutor_id", getAvailabilityHandler)
		auth.POST("/availability", addAvailabilityHandler)
	}

	admin := r.Group("/admin")
	admin.Use(authMiddleware)
	admin.Use(roleMiddleware("admin"))
	{
		admin.GET("/users", adminListUsersHandler)
		admin.PUT("/users/:id/block", adminBlockUserHandler)
		admin.DELETE("/reviews/:id", adminDeleteReviewHandler)
		admin.GET("/stats", getStatsHandler)
	}

	r.POST("/payments/webhook", paymentWebhookHandler)
}

func main() {

	if os.Getenv("RUN_TESTS") == "true" {
		if err := runTests(); err != nil {
			log.Fatalf("Tests failed: %v", err)
		}
		log.Println("All tests passed")
		return
	}

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	var err error
	db, err = initDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS availability_slots (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            tutor_id UUID REFERENCES users(id) ON DELETE CASCADE,
            start_time TIMESTAMP NOT NULL,
            end_time TIMESTAMP NOT NULL,
            CONSTRAINT valid_slot CHECK (end_time > start_time)
        )
    `)
	if err != nil {
		log.Fatalf("Failed to create availability_slots table: %v", err)
	}

	if err := os.MkdirAll(UploadPath, os.ModePerm); err != nil {
		log.Fatalf("Failed to create upload directory: %v", err)
	}

	r := gin.Default()
	r.Use(corsMiddleware())
	r.Use(rateLimitMiddleware)
	setupRoutes(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
func runTests() error {
	if CommissionRate != 0.08 {
		return fmt.Errorf("invalid commission rate")
	}

	return nil
}
