package main

import (
 	"net/http"
    "strings"
    "fmt"
    "io/ioutil"
    "path/filepath"
    "crypto/sha256"
    "encoding/hex"
    "unicode"

    "github.com/disintegration/imaging"
)

func CheckURLExistence(url string) bool {
	resp, err := http.Head(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func IsPicture(url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "image/") {
		return false
	}

	img, err := imaging.Decode(resp.Body)
	if err != nil {
		return false
	}

	return img.Bounds().Max.X > 0 && img.Bounds().Max.Y > 0
}

func SaveImage(url, uuid string) (string, error) {
	if !CheckURLExistence(url) {
		return "", fmt.Errorf("URL does not exist: %s", url)
	}

	if !IsPicture(url) {
		return "", fmt.Errorf("URL is not a picture: %s", url)
	}

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	parts := strings.Split(url, ".")
	ext := parts[len(parts) - 1]
	outputPath := filepath.Join("static/", uuid + "." + ext)
	err = ioutil.WriteFile(outputPath, body, 0644)

	setFile(ext, uuid)
	return outputPath, err
}

func hashString(input string) (string, error) {
	hash := sha256.New()

	_, err := hash.Write([]byte(input))
	if err != nil {
		return "", fmt.Errorf("error hashing string: %w", err)
	}

	digestHex := hex.EncodeToString(hash.Sum(nil))

	return digestHex, nil
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}
