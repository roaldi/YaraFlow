package main

import (
	"bytes"
	"fmt"
	"github.com/hillu/go-yara/v4"
	"io"
	"log"
	"os"
	"strconv"
)

const BufferSize = 1024 * 1024 * 10 // KB -> MB -> 10MB

var LastOffset = 0

func printMatches(item string, m []yara.MatchRule, err error) string {
	if err != nil {
		log.Printf("%s: error: %s", item, err)
		return ""
	}
	if len(m) == 0 {
		return ""
	}
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s: [", item)
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}
	fmt.Fprint(buf, "]")
	return buf.String()

}

func runYara(fileData []byte, fileName string) string {
	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}
	f, err := os.Open(os.Args[2])
	c.AddFile(f, "index")

	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}
	s, _ := yara.NewScanner(r)
	var m yara.MatchRules
	err = s.SetCallback(&m).ScanMem(fileData)
	matches := printMatches(fileName, m, err)

	return matches
}

func fileStream(filename string) {
	f, _ := os.OpenFile(filename, os.O_RDONLY, 0644)

	for {
		buffer := make([]byte, BufferSize)
		bytesread, err := f.Read(buffer)
		returnString := runYara(buffer, filename)
		fmt.Printf("Offset: 0x%s - 0x%s : %s \n", strconv.FormatInt(int64(LastOffset), 16), strconv.FormatInt(int64(LastOffset+bytesread), 16), returnString)
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
			}
			break
		}
		LastOffset += bytesread
	}
}

func main() {
	fileStream(os.Args[1])
}
