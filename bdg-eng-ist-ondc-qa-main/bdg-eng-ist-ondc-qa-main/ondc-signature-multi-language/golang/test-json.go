package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func main() {
	data := map[string]string{
		"test":    "String with special chars: @#$%^&*(){}[]|\\:;\"'<>,.?/~`",
		"unicode": "Unicode test: 你好世界 مرحبا العالم नमस्ते",
	}

	// Test 1: json.Marshal (default)
	jsonBytes1, _ := json.Marshal(data)
	fmt.Println("=== json.Marshal (default) ===")
	fmt.Println(string(jsonBytes1))
	fmt.Println()

	// Test 2: json.Encoder with SetEscapeHTML(false)
	buf := new(bytes.Buffer)
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	encoder.Encode(data)
	fmt.Println("=== json.Encoder with SetEscapeHTML(false) ===")
	fmt.Print(buf.String())
	fmt.Println()

	// Test 3: MarshalIndent (for readability)
	jsonBytes3, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println("=== json.MarshalIndent (default) ===")
	fmt.Println(string(jsonBytes3))
}
