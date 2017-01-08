#ifndef __X86_PE_LIB_H__                                                       
#define __X86_PE_LIB_H__                                                       
                                                                                
#include <sys/compiler.h>                                                       
#include <sys/cpu.h>

#define IMAGE_FILE_MACHINE_I386  0x014c  /* x86 */
#define IMAGE_FILE_MACHINE_IA64  0x0200  /* Intel Itanium */
#define IMAGE_FILE_MACHINE_AMD64 0x8664  /* x64 */

struct image_file_header {
	u16 machine;
	u16 sections;
	u32 timedatestamp;
	u32 sym_table;
	u32 symbols;
	u16 opt_hdr_size;
	u16 flags;
};

struct image_data_directory {
	u32 vaddr;
	u32 size;
};

struct image_optional_header {
	u16   Magic;
	byte  MajorLinkerVersion;
	byte  MinorLinkerVersion;
	u32   SizeOfCode;
	u32   SizeOfInitializedData;
	u32   SizeOfUninitializedData;
	u32   AddressOfEntryPoint;
	u32   BaseOfCode;
	u32   BaseOfData;
	u32   ImageBase;
	u32   SectionAlignment;
	u32   FileAlignment;
	u16   MajorOperatingSystemVersion;
	u16   MinorOperatingSystemVersion;
	u16   MajorImageVersion;
	u16   MinorImageVersion;
	u16   MajorSubsystemVersion;
	u16   MinorSubsystemVersion;
	u32   Win32VersionValue;
	u32   SizeOfImage;
	u32   SizeOfHeaders;
	u32   CheckSum;
	u16   Subsystem;
	u16   DllCharacteristics;
	u32   SizeOfStackReserve;
	u32   SizeOfStackCommit;
	u32   SizeOfHeapReserve;
	u32   SizeOfHeapCommit;
	u32   LoaderFlags;
	u32   NumberOfRvaAndSizes;
	struct image_data_directory data[];
};

struct image_nt_headers {
	u32 signature;
	struct image_file_header header;
	struct image_opt_header opt_header;
};

#endif
