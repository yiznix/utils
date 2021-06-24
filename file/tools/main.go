package main

import (
	"flag"
	"log"
	"yiznix/utils/file"
)

var filePath = flag.String("file", "", "")

func main() {
	flag.Parse()

	err := file.SortLines(*filePath, "/tmp/sorted_file")
	if err != nil {
		log.Fatal(err)
	}
}
