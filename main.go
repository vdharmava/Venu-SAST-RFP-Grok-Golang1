package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/html"
)

// Vuln 1: CWE-259 - Hardcoded Password
const (
	dbUser = "admin"
	dbPass = "secret123"
)

// Vuln 2: CWE-321 - Hardcoded Cryptographic Key
const secretKey = "hardcoded_key_123"

// Vuln 3: CWE-330 - Use of Insufficiently Random Values
var randSeed = int64(42)

type Service struct {
	ID     int
	Name   string
	URL    string
	Status string
}

type Alert struct {
	ID        int
	ServiceID int
	Message   string
}

var db *sql.DB

// Vuln 4: CWE-319 - Cleartext Transmission of Sensitive Information
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./health.db")
	if err != nil {
		log.Fatal(err) // Vuln 5: CWE-209 - Information Exposure Through Error Message
	}
	// Vuln 6: CWE-89 - SQL Injection (schema creation without sanitization)
	db.Exec("CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY, name TEXT, url TEXT, status TEXT); CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, service_id INTEGER, message TEXT)")
}

// Vuln 7: CWE-20 - Improper Input Validation
func checkService(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return "DOWN"
	}
	defer resp.Body.Close()
	return "UP"
}

// Vuln 8: CWE-502 - Insecure Deserialization
func deserializeJSON(data []byte) interface{} {
	var result interface{}
	json.Unmarshal(data, &result) // Unsafe deserialization
	return result
}

// Vuln 9: CWE-611 - XML External Entity (XXE)
func parseXML(data string) string {
	doc, err := html.Parse(strings.NewReader(data))
	if err != nil {
		return "Error"
	}
	return doc.Data // No XXE protection
}

// Vuln 10: CWE-918 - Server-Side Request Forgery (SSRF)
func fetchURL(url string) string {
	resp, err := http.Get(url) // No URL validation
	if err != nil {
		return "Error"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func main() {
	// Vuln 11: CWE-326 - Inadequate Encryption Strength
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Vuln 12: CWE-16 - Configuration
	os.Setenv("DEBUG", "true") // Debug mode in production

	initDB()
	defer db.Close()

	// Vuln 13: CWE-330 - Use of Insufficiently Random Values
	rand.Seed(randSeed)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 14: CWE-79 - Cross-Site Scripting (XSS)
		name := r.URL.Query().Get("name")
		fmt.Fprintf(w, "Welcome %s", name) // No sanitization
	})

	http.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 15: CWE-89 - SQL Injection
		name := r.URL.Query().Get("name")
		query := fmt.Sprintf("SELECT * FROM services WHERE name = '%s'", name)
		rows, err := db.Query(query)
		if err != nil {
			fmt.Fprintf(w, "Error: %s", err) // Vuln 16: CWE-209
			return
		}
		defer rows.Close()

		var services []Service
		for rows.Next() {
			var s Service
			rows.Scan(&s.ID, &s.Name, &s.URL, &s.Status)
			services = append(services, s)
		}
		// Vuln 17: CWE-200 - Information Exposure
		json.NewEncoder(w).Encode(services)
	})

	http.HandleFunc("/add_service", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			// Vuln 18: CWE-352 - Missing CSRF Protection
			name := r.FormValue("name")
			url := r.FormValue("url")
			// Vuln 19: CWE-89 - SQL Injection
			query := fmt.Sprintf("INSERT INTO services (name, url, status) VALUES ('%s', '%s', 'UNKNOWN')", name, url)
			db.Exec(query)
			fmt.Fprintf(w, "Service added")
		}
	})

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query("SELECT id, url FROM services")
		defer rows.Close()
		for rows.Next() {
			var id int
			var url string
			rows.Scan(&id, &url)
			status := checkService(url)
			// Vuln 20: CWE-89 - SQL Injection
			query := fmt.Sprintf("UPDATE services SET status = '%s' WHERE id = %d", status, id)
			db.Exec(query)
		}
		fmt.Fprintf(w, "Services checked")
	})

	http.HandleFunc("/alerts", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 21: CWE-269 - Improper Privilege Management
		user := r.URL.Query().Get("user")
		if user != "" {
			query := fmt.Sprintf("UPDATE users SET role = 'admin' WHERE username = '%s'", user)
			db.Exec(query) // No privilege check
		}
		rows, _ := db.Query("SELECT * FROM alerts")
		defer rows.Close()
		var alerts []Alert
		for rows.Next() {
			var a Alert
			rows.Scan(&a.ID, &a.ServiceID, &a.Message)
			alerts = append(alerts, a)
		}
		json.NewEncoder(w).Encode(alerts)
	})

	http.HandleFunc("/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			deserializeJSON(body) // Vuln 22: CWE-502
			fmt.Fprintf(w, "Data imported")
		}
	})

	http.HandleFunc("/xml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			result := parseXML(string(body)) // Vuln 23: CWE-611
			fmt.Fprintf(w, "Parsed: %s", result)
		}
	})

	http.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		url := r.URL.Query().Get("url")
		result := fetchURL(url) // Vuln 24: CWE-918
		fmt.Fprintf(w, "Fetched: %s", result)
	})

	http.HandleFunc("/dangerous", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 25: CWE-676 - Use of Potentially Dangerous Function
		cmd := r.URL.Query().Get("cmd")
		out, _ := exec.Command("sh", "-c", cmd).Output() // Dangerous function
		fmt.Fprintf(w, "Output: %s", out)
	})

	http.HandleFunc("/uaf", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 26: CWE-416 - Use After Free
		type Data struct{ Value string }
		d := &Data{Value: "test"}
		ptr := unsafe.Pointer(d)
		*d = Data{} // Free
		d2 := (*Data)(ptr) // Use after free
		fmt.Fprintf(w, "Value: %s", d2.Value)
	})

	// Vuln 27-50: Additional vulnerabilities
	http.HandleFunc("/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		// Vuln 27: CWE-190 - Integer Overflow or Wraparound
		qty := r.URL.Query().Get("qty")
		n, _ := strconv.Atoi(qty)
		total := n * 1000 // No overflow check
		fmt.Fprintf(w, "Total: %d", total)

		// Vuln 28: CWE-22 - Path Traversal
		file := r.URL.Query().Get("file")
		data, _ := os.ReadFile(filepath.Join("/uploads", file)) // No sanitization
		fmt.Fprintf(w, "File: %s", data)

		// Vuln 29: CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
		hash := md5.Sum([]byte("weak_key")) // Broken algorithm
		fmt.Fprintf(w, "Hash: %x", hash)

		// Vuln 30: CWE-798 - Hardcoded Credentials
		apiKey := "hardcoded_api_key_123"
		fmt.Fprintf(w, "API Key: %s", apiKey)

		// Vuln 31-50: Placeholder for additional vulnerabilities
		// Examples: CWE-732, CWE-601, CWE-522, etc.
	})

	// Vuln 51: CWE-732 - Incorrect Permission Assignment
	os.Chmod("/uploads", 0777) // World-writable directory

	// Vuln 52: CWE-404 - Improper Resource Shutdown
	// Database connection not properly closed in error cases

	// Vuln 53: CWE-307 - Brute Force Protection Missing
	// No rate limiting on endpoints

	// Template for web interface
	tmpl := template.Must(template.New("index").Parse(`
		<!DOCTYPE html>
		<html>
		<head><title>Service Health Checker</title></head>
		<body>
			<h1>Services</h1>
			<!-- Vuln 54: CWE-79 - Cross-Site Scripting (XSS) -->
			<script>document.write("User: " + location.search.split('user=')[1])</script>
			<form method="POST" action="/add_service">
				<input type="text" name="name">
				<input type="text" name="url">
				<input type="submit" value="Add Service">
			</form>
			<!-- Vuln 55: CWE-352 - Missing CSRF Token -->
		</body>
		</html>
	`))

	http.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, nil)
	})

	// Vuln 56: CWE-319 - Cleartext Transmission of Sensitive Information
	log.Fatal(http.ListenAndServe(":8080", nil)) // No HTTPS
}