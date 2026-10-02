package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	logFileName     = "yara.log"
	auditLogName    = "audit.log"
	initialPreview  = 15
	expandedPreview = 30
)

// ANSI Escape Codes for text formatting
const (
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorBold  = "\033[1m"
)

var keywordsToHighlight = []string{
	"eval", "base64_decode", "gzinflate", "str_rot13", "assert", 
	"system", "exec", "shell_exec", "passthru", "GLOBALS", "WSO", "marvin",
}

var pathRegex = regexp.MustCompile(`(?i)(?:\./|[A-Z]:\\)[\w\-\./\\\\]+\.(?:php|ico)`)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Critical error: %v", err)
	}
}

func run() error {
	logFile, err := os.Open(logFileName)
	if err != nil {
		return fmt.Errorf("failed to open log file %q: %w", logFileName, err)
	}
	defer logFile.Close()

	// Initialize the audit log in append mode (creates if not existing)
	auditFile, err := os.OpenFile(auditLogName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open audit log %q: %w", auditLogName, err)
	}
	defer auditFile.Close()

	stdinReader := bufio.NewReader(os.Stdin)
	scanner := bufio.NewScanner(logFile)

	for scanner.Scan() {
		line := scanner.Text()
		
		targetPath := extractFilePath(line)
		if targetPath == "" {
			continue
		}

		info, err := os.Stat(targetPath)
		if os.IsNotExist(err) || info.IsDir() {
			continue 
		}

		currentLineOffset := 0
		currentLineOffset = printFileLines(targetPath, currentLineOffset, initialPreview)
		
		handleFileAction(stdinReader, auditFile, targetPath, currentLineOffset)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading log file: %w", err)
	}

	return nil
}

func extractFilePath(line string) string {
	found := pathRegex.FindString(line)
	if found == "" {
		return ""
	}
	return filepath.Clean(found)
}

func printFileLines(targetPath string, startLine, linesToRead int) int {
	file, err := os.Open(targetPath)
	if err != nil {
		return startLine
	}
	defer file.Close()

	if startLine == 0 {
		fmt.Printf("\n%s--- PREVIEW: %s ---%s\n", colorBold, targetPath, colorReset)
	} else {
		fmt.Printf("\n%s--- MORE LINES: %s ---%s\n", colorBold, targetPath, colorReset)
	}
	
	scanner := bufio.NewScanner(file)
	currentLine := 0
	printedCount := 0
	
	for scanner.Scan() {
		currentLine++
		if currentLine <= startLine {
			continue
		}

		printedCount++
		rawLine := scanner.Text()
		safeLine := sanitizeTerminalOutput(rawLine)

		if len(safeLine) > 120 {
			safeLine = safeLine[:117] + "..."
		}

		highlightedLine := highlightKeywords(safeLine)
		fmt.Printf("%3d | %s\n", currentLine, highlightedLine)

		if printedCount >= linesToRead {
			break
		}
	}
	
	fmt.Println(strings.Repeat("-", 40))
	return currentLine
}

func highlightKeywords(input string) string {
	output := input
	for _, kw := range keywordsToHighlight {
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(kw))
		output = re.ReplaceAllStringFunc(output, func(matched string) string {
			return colorRed + colorBold + matched + colorReset
		})
	}
	return output
}

func sanitizeTerminalOutput(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return '?' 
		}
		return r
	}, s)
}

// logAction records decisions locally into the append-only audit trail
func logAction(auditWriter io.Writer, action, path string) {
	timestamp := time.Now().Format(time.RFC3339)
	entry := fmt.Sprintf("[%s] ACTION=%s FILE=%s\n", timestamp, action, path)
	if _, err := auditWriter.Write([]byte(entry)); err != nil {
		log.Printf("[WARNING] Could not write to audit log: %v", err)
	}
}

func handleFileAction(reader *bufio.Reader, auditWriter io.Writer, targetPath string, initialOffset int) {
	offset := initialOffset

	for {
		fmt.Printf("-> Action for %s? [y=Delete, n=Skip, v=View More]: ", filepath.Base(targetPath))
		
		response, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			log.Printf("Error reading input: %v", err)
			return
		}

		input := strings.ToLower(strings.TrimSpace(response))
		if len(input) == 0 {
			continue
		}

		switch input {
		case "y":
			if err := os.Remove(targetPath); err != nil {
				log.Printf("[ERROR] Failed to delete %s: %v", targetPath, err)
				logAction(auditWriter, "DELETE_FAILED", targetPath)
			} else {
				log.Printf("[DELETED] %s", targetPath)
				logAction(auditWriter, "DELETED", targetPath)
			}
			return

		case "n":
			log.Printf("[SKIPPED] %s", targetPath)
			logAction(auditWriter, "SKIPPED", targetPath)
			return

		case "v":
			offset = printFileLines(targetPath, offset, expandedPreview)

		default:
			fmt.Println("Invalid option. Please use y, n, or v.")
		}
	}
}
