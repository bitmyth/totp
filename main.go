package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

func moveCursorBegin() string {
	return "\r"
}

func main() {
	secret, b := os.LookupEnv("TOTP_SECRET")
	if !b {
		log.Println("no totp_secret environment variable setup")
		return
	}

	//ticker := time.NewTicker(5 * time.Second).C
	for {
		now := time.Now().Unix()
		q := now / 30
		r := now % 30
		//println(r, 30-r)

		c := ComputeCode(secret, q)

		for i := int64(0); i < 30-r; i++ {
			remainSeconds := 30 - r - i
			remainSecondsPrompt := fmt.Sprintf(" ( %2ds ) ", remainSeconds)
			print(moveCursorBegin() + strconv.Itoa(c) + remainSecondsPrompt)
			time.Sleep(time.Second)
		}

		//<-ticker
		//time.Sleep(time.Duration(30-r) * time.Second)
	}
}

// ComputeCode Copy from https://github.com/dgryski/dgoogauth
func ComputeCode(secret string, value int64) int {

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return -1
	}

	hash := hmac.New(sha1.New, key)
	err = binary.Write(hash, binary.BigEndian, value)
	if err != nil {
		return -1
	}
	h := hash.Sum(nil)

	offset := h[19] & 0x0f

	truncated := binary.BigEndian.Uint32(h[offset : offset+4])

	truncated &= 0x7fffffff
	code := truncated % 1000000

	return int(code)
}
