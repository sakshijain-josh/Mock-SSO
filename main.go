package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

type ValidateRequest struct {
	Token string `json:"token"`
}

type TokenPayload struct {
	Username  string `json:"username"`
	Timestamp string `json:"timestamp"`
}

type ValidateResponse struct {
	Payload TokenPayload `json:"payload"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func generateToken(username string) string {
	// Create payload
	payload := TokenPayload{
		Username:  username,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	payloadJSON, _ := json.Marshal(payload)
	encodedPayload := base64.StdEncoding.EncodeToString(payloadJSON)

	mockHeader := base64.StdEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	mockSignature := base64.StdEncoding.EncodeToString([]byte("mock_signature_" + username))

	return fmt.Sprintf("%s.%s.%s", mockHeader, encodedPayload, mockSignature)
}

func validateToken(token string) (*TokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token structure")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding")
	}

	var payload TokenPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid token payload")
	}

	if payload.Username == "" || payload.Timestamp == "" {
		return nil, fmt.Errorf("token missing required claims")
	}

	return &payload, nil
}

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request body"})
		return
	}

	// Accept any username/password (mock authentication)
	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Username and password required"})
		return
	}

	token := generateToken(req.Username)

	log.Printf("Login successful for user: %s", req.Username)
	log.Printf("Generated token: %s", token)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{AccessToken: token})
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request body"})
		return
	}

	payload, err := validateToken(req.Token)
	if err != nil {
		log.Printf("Token validation failed: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
		return
	}

	log.Printf("Token validated successfully for user: %s", payload.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ValidateResponse{Payload: *payload})
}

func main() {
	http.HandleFunc("/api/login", enableCORS(handleLogin))
	http.HandleFunc("/api/validate", enableCORS(handleValidate))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "index.html")
		} else {
			http.NotFound(w, r)
		}
	})

	port := ":5000"
	log.Printf("Starting Mock SSO server on http://localhost%s", port)
	log.Printf("Open http://localhost:5000 in your browser")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
