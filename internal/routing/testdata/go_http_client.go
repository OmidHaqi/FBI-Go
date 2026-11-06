package main

import (
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	client := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
	response, err := client.Get("http://service:8080/go-client")
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		panic(response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil {
		panic(err)
	}
	if string(body) != "fbi-go-test-ok\n" {
		panic("unexpected HTTP body")
	}
	_, _ = os.Stdout.Write(body)
}
