package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	logFile := "yara.log"
	f, err := os.Open(logFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ".php") || strings.Contains(line, ".ico") {
			tt := strings.Replace(line, "wordpress ./", "", -1)
			if confirm(fmt.Sprintf("Delete %s?", tt), 2) {
				if err := deleteFile(tt); err != nil {
					log.Printf("Error deleting %s: %v\n", tt, err)
				} else {
					log.Printf("Deleted %s\n", tt)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func confirm(s string, tries int) bool {
	r := bufio.NewReader(os.Stdin)

	for ; tries > 0; tries-- {
		fmt.Printf("%s [y/n]: ", s)

		res, err := r.ReadString('\n')
		if err != nil {
			log.Fatal(err)
		}

		switch strings.ToLower(strings.TrimSpace(res))[0] {
		case 'y':
			return true
		case 'n':
			return false
		}
	}

	return false
}

func deleteFile(filename string) error {
	cmd := exec.Command("rm", filename)
	cmd.Stdout = os.Stdout
	return cmd.Run()
}
