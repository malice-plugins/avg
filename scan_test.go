package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"testing"
)

func parse(output string, path string) ResultsData {

	avg := ResultsData{
		Infected: false,
		Engine:   "test",
	}

	colonSeparated := []string{}

	lines := strings.Split(output, "\n")
	// Extract Virus string and extract colon separated lines into an slice
	for _, line := range lines {
		if len(line) != 0 {
			if strings.Contains(line, ":") {
				colonSeparated = append(colonSeparated, line)
			}
			if strings.Contains(line, path) {
				pathVirusString := strings.Split(line, "  ")
				avg.Result = strings.TrimSpace(pathVirusString[1])
			}
		}
	}
	return avg
}

// TestParseResult tests the ParseAVGOutput function.
func TestParseResult(t *testing.T) {

	r, err := ioutil.ReadFile("tests/av_scan.out")
	if err != nil {
		fmt.Print(err)
	}

	results := parse(string(r), "/malware/EICAR")
	if err != nil {
		log.Fatal(err)
	}

	if true {
		t.Log("Result: ", results.Result)
		t.Log("Engine: ", results.Engine)
	}

}
