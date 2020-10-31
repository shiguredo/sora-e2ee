package main

import (
	"github.com/shiguredo/sora-e2ee-go/internal/e2ee"
)

func main() {
	c := make(chan struct{}, 0)
	e2ee.RegisterCallbacks()
	<-c
}
