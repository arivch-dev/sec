package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {

	if len(os.Args) < 2 {
		log.Fatal("Укажите порт: go run backend.go <port>")
	}
	port := os.Args[1]

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		time.Sleep(100 * time.Millisecond)

		fmt.Fprintf(w, "Привет от бэкенда на порту %s!\n", port)
		log.Printf("Обработан запрос от %s\n", r.RemoteAddr)
	})

	log.Printf("Бэкенд запущен на порту %s\n", port)
	http.ListenAndServe(":"+port, nil)
}
