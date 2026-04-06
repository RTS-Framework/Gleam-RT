package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RTS-Framework/GRT-Develop/shield"
)

var decoy = []byte{
	0x31, 0xC0, //  xor eax, eax
	0xC3, //        ret
}

func main() {
	dump("x86")
	dump("x64")
}

func dump(arch string) {
	inst, err := os.ReadFile(fmt.Sprintf("shield_%s.bin", arch))
	checkError(err)

	template := make([]byte, shield.StubSize)
	template[0] = shield.StubMagic
	stub, err := shield.Set(template, inst, decoy)
	checkError(err)

	path := fmt.Sprintf("../asm/inst/shield_%s.inst", arch)
	data := dumpBytesHex(stub)
	err = os.WriteFile(path, data, 0644)
	checkError(err)

	path, err = filepath.Abs(path)
	checkError(err)
	fmt.Println("dump:", path)
}

func dumpBytesHex(b []byte) []byte {
	n := len(b)
	buffer := bytes.Buffer{}
	buffer.Grow(len("0FFh, ")*n - len(", "))
	buf := make([]byte, 2)
	var counter = 0
	for i := 0; i < n; i++ {
		if counter == 0 {
			buffer.WriteString("  db ")
		}
		hex.Encode(buf, b[i:i+1])
		buffer.WriteString("0")
		buffer.Write(bytes.ToUpper(buf))
		buffer.WriteString("h")
		if i == n-1 {
			buffer.WriteString("\r\n")
			break
		}
		counter++
		if counter != 8 {
			buffer.WriteString(", ")
			continue
		}
		counter = 0
		buffer.WriteString("\r\n")
	}
	return buffer.Bytes()
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
