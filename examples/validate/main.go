package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/dsggregory/jwtv"
)

func main() {
	fmt.Println("Enter token followed by ^D:")
	token := ""
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		token += scanner.Text()
	}
	if scanner.Err() != nil {
		panic(scanner.Err())
	}

	req, _ := http.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+string(token))

	jv, _ := jwtv.NewJWTValidator()

	claims, err := jv.ParseWithoutValidation(req)
	data, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(string(data))
}
