#include "c_types.h"
#include "win_types.h"
#include "lib_memory.h"
#include "pe_image.h"

// not search the section that named ".text".
//
// this is more robust than checking for the section name ".text," because
// the code section of some PE files (such as those generated via packers,
// LLVM, Clang, or custom linker scripts) is not necessarily named ".text,"
// whereas an executable section will always carry the `IMAGE_SCN_MEM_EXECUTE`.
//
// another benefit is that the ".text" string does not appear in the runtime.
void ParsePEImage(void* address, PE_Image* image)
{
    uintptr imageAddr = (uintptr)address;
    uint32  hdrOffset = *(uint32*)(imageAddr + DOS_HEADER_SIZE - 4);
    // parse PE headers
    Image_NTHeaders*      ntHeaders  = (Image_NTHeaders*)(imageAddr + hdrOffset);
    Image_FileHeader*     fileHeader = &ntHeaders->FileHeader;
    Image_OptionalHeader* optHeader  = &ntHeaders->OptionalHeader;
    // get address of first section header
    uintptr fileAddr = imageAddr + hdrOffset + sizeof(ntHeaders->Signature);
    uintptr optAddr  = fileAddr + sizeof(Image_FileHeader);
    uint32  optSize  = fileHeader->SizeOfOptionalHeader;
    // search the first executable section
    Image_SectionHeader* section = (Image_SectionHeader*)(optAddr + optSize);
    for (uint16 i = 0; i < fileHeader->NumberOfSections; i++)
    {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            // use mem_copy for reduce instruction size
            mem_copy(&image->Text, section, sizeof(Image_SectionHeader));
            break;
        }
        section++;
    }
    // store the parsed result
    image->EntryPoint = imageAddr + optHeader->AddressOfEntryPoint;
    image->ImageBase  = optHeader->ImageBase;
    image->ImageSize  = optHeader->SizeOfImage;
    // use mem_copy for reduce instruction size
    mem_copy(&image->FileHeader, fileHeader, sizeof(Image_FileHeader));
    mem_copy(&image->OptionalHeader, optHeader, sizeof(Image_OptionalHeader));
}
