package main

import (
	"log"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "collect":
			runCollect()
			return
		case "all":
			runCollect()
			runTest()
			return
		case "test", "run":
			runTest()
			return
		case "help", "-h", "--help":
			log.Println("usage: proxy-tester [collect|test|all]  (default: test)")
			return
		}
	}
	runTest()
}
