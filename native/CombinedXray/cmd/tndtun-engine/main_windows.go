package main

import (
	"fmt"
	"kindlyvpn/native/internal/desktop"
	"os"
)

func main() {
	out := os.Stdout
	os.Stdout = os.Stderr
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Fprintln(out, desktop.Version)
		return
	}
	if e := desktop.Serve(os.Stdin, out); e != nil {
		fmt.Fprintln(out, `{"event":"fatal","error":"Не удалось открыть защищённое хранилище. Данные сохранены; проверьте права пользователя."}`)
		os.Exit(1)
	}
}
