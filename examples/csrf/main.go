package main

import (
	_ "embed"
	"log"
	"net/http"
	"text/template"

	"github.com/danecwalker/gosec/middleware/csrf"
)

//go:embed index.html
var indexHTML string

func main() {
	mux := http.NewServeMux()

	// Configure CSRF middleware
	csrfMiddleware := csrf.Middleware(nil) // Use default config
	setter := csrf.TemplateSetter(nil)     // Use default config

	mux.HandleFunc("/{path}", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not found", http.StatusNotFound)
	})

	// Your main application handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mapJoiner := setter(w)
		err := template.Must(template.New("").Parse(indexHTML)).Execute(w, mapJoiner(map[string]any{}))

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	handler := csrfMiddleware(mux)

	log.Println("Server running on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}
