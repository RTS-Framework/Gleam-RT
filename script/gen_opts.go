package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/RTS-Framework/GRT-Develop/option"
)

func main() {
	opts := option.Options{
		ImagePinningHash: option.Hash("test.exe"),
		ShieldModuleHash: option.Hash("test.dll"),
		ShieldEntryPoint: 0x12345678,
	}

	template := make([]byte, option.StubSize)
	template[0] = option.StubMagic
	stub, err := option.Set(template, &opts)
	checkError(err)

	data := dumpBytesHex(stub)
	fmt.Println(data)

	err = os.WriteFile("../asm/inst/option.inst", []byte(data), 0644)
	checkError(err)
}

func dumpBytesHex(b []byte) string {
	n := len(b)
	builder := bytes.Buffer{}
	builder.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			builder.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		builder.WriteString("0")
		builder.Write(bytes.ToUpper(buf))
		builder.WriteString("h")
		if i == n-1 {
			builder.WriteString("\r\n")
			break
		}
		counter++
		if counter != 8 {
			builder.WriteString(", ")
			continue
		}
		counter = 0
		builder.WriteString("\r\n")
	}
	return builder.String()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
