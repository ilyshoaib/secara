package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func vulnerableSQL(db *sql.DB, userInput string) {
	// Rule: SQL005
	query := "SELECT * FROM users WHERE name = '" + userInput + "'"
	db.Query(query)

	query2 := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userInput)
	db.Exec(query2)
}

func vulnerableCmd(userInput string) {
	// Rule: CMD005
	cmd := exec.Command("sh", "-c", "echo " + userInput)
	cmd.Run()

	cmd2 := exec.Command("bash", "-c", fmt.Sprintf("ls %s", userInput))
	cmd2.Run()
}

func vulnerableSSRF(userInput string) {
	// Rule: SSRF003
	url := "https://api.example.com/data?user=" + userInput
	http.Get(url)

	url2 := fmt.Sprintf("http://internal-admin/%s", userInput)
	http.Post(url2, "application/json", nil)
}

func vulnerablePathTraversal(userInput string) {
	// Rule: PATH004
	path := "/var/log/" + userInput
	os.Open(path)

	path2 := filepath.Join("/app/data", userInput)
	os.ReadFile(path2)
}

func main() {
	fmt.Println("This is a vulnerable Go file for Secara testing.")
}
