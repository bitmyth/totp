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

	for {
		now := time.Now().Unix()
		period := int64(30)
		q := now / period
		r := now % period

		c := ComputeCode(secret, q)

		for i := int64(0); i < period-r; i++ {
			remainSeconds := period - r - i
			remainSecondsPrompt := fmt.Sprintf(" ( %2ds ) ", remainSeconds)
			print(moveCursorBegin() + strconv.Itoa(c) + remainSecondsPrompt)

			time.Sleep(time.Second)
		}
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
