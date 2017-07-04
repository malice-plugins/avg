package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"testing"
)

// TestParseResult tests the ParseAVGOutput function.
func TestParseResult(t *testing.T) {

	r, err := ioutil.ReadFile("tests/av_scan.out")
	if err != nil {
		fmt.Print(err)
	}

	results, err := ParseAVGOutput(string(r), nil, "/malware/EICAR")
	if err != nil {
		log.Fatal(err)
	}

	if true {
		t.Log("Result: ", results.Result)
		t.Log("Engine: ", results.Engine)
	}

}
