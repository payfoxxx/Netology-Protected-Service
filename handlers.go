package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
)

// RegisterHandler обрабатывает регистрацию нового пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody RegisterRequest
	if err := parseJSONRequest(r, &requestBody); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateRegisterRequest(&requestBody); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	existsEmail, err := UserExistsByEmail(requestBody.Email)

	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if existsEmail {
		sendErrorResponse(w, "this email already registered", http.StatusConflict)
		return
	}

	hashedPassword, err := HashPassword(requestBody.Password)

	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user, err := CreateUser(requestBody.Email, requestBody.Username, hashedPassword)

	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token, err := GenerateToken(*user)

	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, http.StatusCreated)

}

// LoginHandler обрабатывает вход пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody LoginRequest
	if err := parseJSONRequest(r, &requestBody); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateLoginRequest(&requestBody); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := GetUserByEmail(requestBody.Email)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
			return
		} else {
			sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if !CheckPassword(requestBody.Password, user.PasswordHash) {
		sendErrorResponse(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	token, err := GenerateToken(*user)
	if err != nil {
		sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, AuthResponse{Token: token, User: *user}, http.StatusOK)
}

// ProfileHandler возвращает профиль текущего пользователя
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, ok := GetUserIDFromContext(r)
	if !ok {
		sendErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := GetUserByID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendErrorResponse(w, "User not found", http.StatusNotFound)
			return
		} else {
			sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	sendJSONResponse(w, *user, http.StatusOK)
}

// HealthHandler проверяет состояние сервиса
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем подключение к БД
	if db != nil {
		if err := db.Ping(); err != nil {
			http.Error(w, "Database connection failed", http.StatusServiceUnavailable)
			return
		}
	}

	// Возвращаем статус OK
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{
		"status":  "ok",
		"message": "Service is running",
	}
	json.NewEncoder(w).Encode(response)
}

// sendJSONResponse отправляет JSON ответ (вспомогательная функция)
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse отправляет JSON ответ с ошибкой (вспомогательная функция)
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]string{"error": message}
	json.NewEncoder(w).Encode(response)
}

// parseJSONRequest парсит JSON из тела запроса (вспомогательная функция)
func parseJSONRequest(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body is empty")
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Строгая проверка полей

	return decoder.Decode(v)
}

// validateRegisterRequest валидирует данные регистрации
func validateRegisterRequest(req *RegisterRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}

	if err := ValidateEmail(req.Email); err != nil {
		return err
	}

	if err := ValidatePassword(req.Password); err != nil {
		return err
	}

	if len(req.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters")
	}

	if len(req.Username) > 20 {
		return fmt.Errorf("username can't be more than 20 characters")
	}

	usernamePattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]+$`)
	if !usernamePattern.MatchString(req.Username) {
		return fmt.Errorf("username contains incorrect symbols")
	}
	return nil
}

// validateLoginRequest валидирует данные входа
func validateLoginRequest(req *LoginRequest) error {
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}
