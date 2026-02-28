package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type Post struct {
	UserId int    `json:"userId"`
	Id     int    `json:"id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

func main() {
	url := "https://jsonplaceholder.typicode.com/posts/1"

	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Error fetching data: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Error: received non-OK HTTP status %d", resp.StatusCode)
	}

	var post Post
	err = json.NewDecoder(resp.Body).Decode(&post)
	if err != nil {
		log.Fatalf("Error decoding JSON: %v", err)
	}

	log.Printf("Post ID: %d, Title: %s", post.Id, post.Title)
}
