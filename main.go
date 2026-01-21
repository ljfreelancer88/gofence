package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	logFileName     = "yara.log"
	maxConfirmTries = 2
	searchPrefix    = "wordpress ./"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	f, err := os.Open(logFileName)
	if err != nil {
		return fmt.Errorf("failed to open log file %q: %w", logFileName, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if shouldProcess(line) {
			processLine(line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading log file: %w", err)
	}

	return nil
}

// shouldProcess checks if a line contains files that should be processed.
func shouldProcess(line string) bool {
	return strings.Contains(line, ".php") || strings.Contains(line, ".ico")
}

// processLine handles the confirmation and deletion of a file from a log line.
func processLine(line string) {
	filepath := strings.TrimPrefix(line, searchPrefix)
	
	if !confirm(fmt.Sprintf("Delete %s?", filepath), maxConfirmTries) {
		return
	}

	if err := os.Remove(filepath); err != nil {
		log.Printf("Error deleting %s: %v", filepath, err)
		return
	}
	
	log.Printf("Successfully deleted %s", filepath)
}

// confirm prompts the user for confirmation with a specified number of attempts.
func confirm(prompt string, maxTries int) bool {
	reader := bufio.NewReader(os.Stdin)
	
	for i := 0; i < maxTries; i++ {
		fmt.Printf("%s [y/n]: ", prompt)
		
		response, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v", err)
			return false
		}

		normalized := strings.ToLower(strings.TrimSpace(response))
		if len(normalized) == 0 {
			continue
		}

		switch normalized[0] {
		case 'y':
			return true
		case 'n':
			return false
		}
	}
	
	return false
}
