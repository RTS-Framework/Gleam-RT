package gleamrt

import (
	"fmt"

	"github.com/RTS-Framework/GRT-Develop/info"
)

// Info contains runtime information.
type Info struct {
	Version string `json:"version"`
	Hash    uint64 `json:"hash"`
	Size    int    `json:"size"`
	Flags   uint32 `json:"flags"`
}

// ConvertRawInfo is used to convert raw runtime info to go type.
func ConvertRawInfo(info *info.Info) *Info {
	ver := info.Version
	a := int((ver >> 16) & 0xFF)
	b := int((ver >> 8) & 0xFF)
	c := int((ver >> 0) & 0xFF)
	vs := fmt.Sprintf("v%d.%d.%d", a, b, c)
	return &Info{
		Version: vs,
		Hash:    info.Hash,
		Size:    int(info.Size),
		Flags:   info.Flags,
	}
}
