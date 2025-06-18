package main

import "github.com/astrorick/semantika"

func main() {
	v1, _ := semantika.New("1.2.3")
	v2, _ := semantika.New("1.1.2")
	println(v1.OlderThanOrEquals(v2))
}
