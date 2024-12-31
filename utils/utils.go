package utils

import (
	"github.com/twinj/uuid"
	"math/rand"
	"encoding/json"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func NewUUIDV4() string {
	return uuid.NewV4().String()
}



func AddStr(in string, mac string) (out string) {
	var arr []string = []string{}
	if in != "" {
		json.Unmarshal([]byte(in), &arr)
	}
	arr = append(arr, mac)
	outb, _ := json.Marshal(arr)
	out = string(outb)
	return
}

func RemoveStr(in string, mac string) (out string) {
	var arr []string = []string{}
	var outarr []string
	if in != "" {
		json.Unmarshal([]byte(in), &arr)
	}
	for _, el := range arr {
		if el != mac {
			outarr = append(outarr, el)
		}
	}
	outb, _ := json.Marshal(outarr)
	out = string(outb)
	return
}

func GetFirst(in string) (out string) {
	var arr []string = []string{}
	if in == "" {
		return ""
	}
	json.Unmarshal([]byte(in), &arr)
	return arr[0]
}

func GetMacByCookie(m string, c string, cookie string) (mac string) {
	var macs, cookies []string
	json.Unmarshal([]byte(m), &macs)
	json.Unmarshal([]byte(c), &cookies)
	for i, c := range cookies {
		if string(c) == cookie {
			return macs[i]
		}
	}
	return ""
}
