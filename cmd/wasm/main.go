package main

import (
	e2ee "github.com/shiguredo/sora-e2ee"
)

// Version は Makefile 側で flag を利用して設定する
var Version = "dev"

func main() {
	c := make(chan struct{})
	e2ee.RegisterCallbacks(Version)
	<-c
}
