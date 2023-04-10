package phpass

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

type PasswordHash struct {
	itoa64       string
	iterationCnt int
	portableHash bool
	randomState  string
}

func NewPasswordHash(iterationCnt int, portableHash bool) *PasswordHash {
	rand.Seed(time.Now().UnixNano())
	return &PasswordHash{
		itoa64:       "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		iterationCnt: iterationCnt,
		portableHash: portableHash,
		randomState:  fmt.Sprintf("%d%s%d", time.Now().UnixNano(), strconv.Itoa(rand.Int()), rand.Int()),
	}
}

func (p *PasswordHash) GetRandomBytes(count int) []byte {
	output := []byte{}
	fh, err := os.Open("/dev/urandom")
	if err == nil {
		output = make([]byte, count)
		fh.Read(output)
		fh.Close()
	}
	if len(output) < count {
		output = []byte{}
		for i := 0; i < count; i += 16 {
			p.randomState = fmt.Sprintf("%x", md5.Sum([]byte(p.randomState)))
			output = append(output, []byte(fmt.Sprintf("%x", md5.Sum([]byte(p.randomState))))...)
		}
		output = output[:count]
	}
	return output
}

func (p *PasswordHash) Encode64(input []byte, count int) string {
	output := ""
	i := 0
	for i < count {
		value := int(input[i])
		output += string(p.itoa64[value&0x3f])
		if i+1 < count {
			value |= int(input[i+1]) << 8
		}
		output += string(p.itoa64[(value>>6)&0x3f])
		i++
		if i >= count {
			break
		}
		if i+1 < count {
			value |= int(input[i+1]) << 16
		}
		output += string(p.itoa64[(value>>12)&0x3f])
		i++
		if i >= count {
			break
		}
		output += string(p.itoa64[(value>>18)&0x3f])
		i++
	}
	return output
}

func (p *PasswordHash) GensaltPrivate(input []byte) string {
	output := "$P$"
	output += string(p.itoa64[min(p.iterationCnt+5, 30)])
	output += p.Encode64(input, 6)
	return output
}

func (p *PasswordHash) CryptPrivate(password, setting string) string {
	output := "*0"
	if setting[:2] == output {
		output = "*1"
	}
	if setting[:3] != "$P$" {
		return output
	}
	countLog2 := strings.Index(p.itoa64, string(setting[3]))
	if countLog2 < 7 || countLog2 > 30 {
		return output
	}
	count := 1 << uint(countLog2)
	salt := setting[4:12]
	if len(salt) != 8 {
		return output
	}
	hash := md5.Sum([]byte(salt + password))
	for i := count; i > 0; i-- {
		hash = md5.Sum(append(hash[:], []byte(password)...))
	}
	output = setting[:12]
	output += p.Encode64(hash[:], 16)
	return output
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// HashPassword creates a hashed password for the given plain text password.
func (p *PasswordHash) HashPassword(password string) (string, error) {
	if p.portableHash {
		random := p.GetRandomBytes(6)
		salt := p.GensaltPrivate(random)
		hash := p.CryptPrivate(password, salt)
		if len(hash) == 34 {
			return hash, nil
		}
	}
	return "", fmt.Errorf("failed to create password hash")
}

func (p *PasswordHash) CheckPassword(password, storedHash string) bool {
	hash := p.CryptPrivate(password, storedHash)
	if hash[0] == '*' {
		hash = p.CryptPrivate(password, storedHash)
	}
	return hash == storedHash
}
