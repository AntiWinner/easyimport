#ifndef _EASYIMPORT_HPP
#define _EASYIMPORT_HPP
 
#define _MIN(a, b)  (((a) < (b)) ? (a) : (b))
#ifndef WIN32
extern "C" unsigned __int64 __readgsqword(unsigned long);
extern "C" __declspec(dllimport) void* LoadLibraryW(const wchar_t* lpLibFileName);
#endif

namespace easyimport
{

	// trust me i'm not a fan of this either :/
#pragma region windefs
	typedef char BYTE;
	typedef void* PVOID;
	typedef unsigned long ULONG;
	typedef short SHORT;
	typedef unsigned long long ULONGLONG;
	typedef void* HANDLE;
	typedef unsigned short USHORT;
	typedef unsigned char UCHAR;
	typedef unsigned long DWORD;
	typedef long LONG;
	typedef long long LONGLONG;
	typedef unsigned short WORD;
	typedef BYTE* LPBYTE;
	typedef WORD* PWORD;
	typedef DWORD* PDWORD;
	typedef char CHAR;
	typedef CHAR* PCHAR, * LPCH, * PCH;
	typedef void* LPVOID;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_DIRECTORY_ENTRY_EXPORT        0

	struct UNICODE_STRING {
		unsigned short Length;
		unsigned short MaximumLength;
		wchar_t* Buffer;
	};

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct  LDR_DATA_ENTRY {
		LIST_ENTRY              InMemoryOrderModuleList;
		PVOID                   BaseAddress;
		PVOID                   EntryPoint;
		ULONG                   SizeOfImage;
		UNICODE_STRING          FullDllName;
		UNICODE_STRING          BaseDllName;
		ULONG                   Flags;
		SHORT                   LoadCount;
		SHORT                   TlsIndex;
		LIST_ENTRY              HashTableEntry;
		ULONG                   TimeDateStamp;
	} LDR_DATA_ENTRY, * PLDR_DATA_ENTRY;

	typedef struct  _PEB_LDR_DATA {
		BYTE       Reserved1[8];
		PVOID      Reserved2[3];
		LIST_ENTRY InMemoryOrderModuleList;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct  _LDR_MODULE
	{
		LIST_ENTRY              InLoadOrderModuleList;
		LIST_ENTRY              InMemoryOrderModuleList;
		LIST_ENTRY              InInitializationOrderModuleList;
		PVOID                   BaseAddress;
		PVOID                   EntryPoint;
		ULONG                   SizeOfImage;
		UNICODE_STRING          FullDllName;
		UNICODE_STRING          BaseDllName;
		ULONG                   Flags;
		SHORT                   LoadCount;
		SHORT                   TlsIndex;
		LIST_ENTRY              HashTableEntry;
		ULONG                   TimeDateStamp;
	} LDR_MODULE, * PLDR_MODULE;

	typedef struct  _RTL_DRIVE_LETTER_CURDIR
	{
		USHORT					Flags;
		USHORT					Length;
		ULONG					TimeStamp;
		UNICODE_STRING			DosPath;
	} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

	typedef struct  _RTL_USER_PROCESS_PARAMETERS
	{
		ULONG					MaximumLength;
		ULONG					Length;
		ULONG					Flags;
		ULONG					DebugFlags;
		PVOID					ConsoleHandle;
		ULONG					ConsoleFlags;
		HANDLE					StdInputHandle;
		HANDLE					StdOutputHandle;
		HANDLE					StdErrorHandle;
		UNICODE_STRING			CurrentDirectoryPath;
		HANDLE					CurrentDirectoryHandle;
		UNICODE_STRING			DllPath;
		UNICODE_STRING			ImagePathName;
		UNICODE_STRING			CommandLine;
		PVOID					Environment;
		ULONG					StartingPositionLeft;
		ULONG					StartingPositionTop;
		ULONG					Width;
		ULONG					Height;
		ULONG					CharWidth;
		ULONG					CharHeight;
		ULONG					ConsoleTextAttributes;
		ULONG					WindowFlags;
		ULONG					ShowWindowFlags;
		UNICODE_STRING			WindowTitle;
		UNICODE_STRING			DesktopName;
		UNICODE_STRING			ShellInfo;
		UNICODE_STRING			RuntimeData;
		RTL_DRIVE_LETTER_CURDIR	DLCurrentDirectory[0x20];
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	typedef union _LARGE_INTEGER {
		struct {
			DWORD LowPart;
			LONG HighPart;
		} DUMMYSTRUCTNAME;
		struct {
			DWORD LowPart;
			LONG HighPart;
		} u;
		LONGLONG QuadPart;
	} LARGE_INTEGER;

	typedef struct  _PEB {
		BYTE                          Reserved1[2];
		BYTE                          BeingDebugged;
		BYTE                          Reserved2[1];
		PVOID                         Reserved3[2];
		PPEB_LDR_DATA                 Ldr;
		PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
		ULONGLONG SubSystemData;
		ULONGLONG ProcessHeap;
		ULONGLONG FastPebLock;
		ULONGLONG AtlThunkSListPtr;
		ULONGLONG IFEOKey;
		union
		{
			ULONG CrossProcessFlags;
			struct
			{
				ULONG ProcessInJob : 1;
				ULONG ProcessInitializing : 1;
				ULONG ProcessUsingVEH : 1;
				ULONG ProcessUsingVCH : 1;
				ULONG ProcessUsingFTH : 1;
				ULONG ProcessPreviouslyThrottled : 1;
				ULONG ProcessCurrentlyThrottled : 1;
				ULONG ProcessImagesHotPatched : 1;
				ULONG ReservedBits0 : 24;
			};
		};
		UCHAR Padding1[4];
		union
		{
			ULONGLONG KernelCallbackTable;
			ULONGLONG UserSharedInfoPtr;
		};
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		ULONGLONG ApiSetMap;
		ULONG TlsExpansionCounter;
		UCHAR Padding2[4];
		ULONGLONG TlsBitmap;
		ULONG TlsBitmapBits[2];
		ULONGLONG ReadOnlySharedMemoryBase;
		ULONGLONG SharedData;
		ULONGLONG ReadOnlyStaticServerData;
		ULONGLONG AnsiCodePageData;
		ULONGLONG OemCodePageData;
		ULONGLONG UnicodeCaseTableData;
		ULONG NumberOfProcessors;
		ULONG NtGlobalFlag;
		union _LARGE_INTEGER CriticalSectionTimeout;
		ULONGLONG HeapSegmentReserve;
		ULONGLONG HeapSegmentCommit;
		ULONGLONG HeapDeCommitTotalFreeThreshold;
		ULONGLONG HeapDeCommitFreeBlockThreshold;
		ULONG NumberOfHeaps;
		ULONG MaximumNumberOfHeaps;
		ULONGLONG ProcessHeaps;
		ULONGLONG GdiSharedHandleTable;
		ULONGLONG ProcessStarterHelper;
		ULONG GdiDCAttributeList;
		UCHAR Padding3[4];
		ULONGLONG LoaderLock;
		ULONG OSMajorVersion;
		ULONG OSMinorVersion;
		USHORT OSBuildNumber;
	} PEB, * PPEB;

	typedef struct _ACTIVATION_CONTEXT _ACTIVATION_CONTEXT, * P_ACTIVATION_CONTEXT;
	typedef struct _ACTIVATION_CONTEXT_DATA _ACTIVATION_CONTEXT_DATA, * P_ACTIVATION_CONTEXT_DATA;

	typedef struct  _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			struct
			{
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		union
		{
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
		_ACTIVATION_CONTEXT* EntryPointActivationContext;
		PVOID PatchInformation;
		LIST_ENTRY ForwarderLinks;
		LIST_ENTRY ServiceTagLinks;
		LIST_ENTRY StaticLinks;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
		WORD   e_magic;                     // Magic number
		WORD   e_cblp;                      // Bytes on last page of file
		WORD   e_cp;                        // Pages in file
		WORD   e_crlc;                      // Relocations
		WORD   e_cparhdr;                   // Size of header in paragraphs
		WORD   e_minalloc;                  // Minimum extra paragraphs needed
		WORD   e_maxalloc;                  // Maximum extra paragraphs needed
		WORD   e_ss;                        // Initial (relative) SS value
		WORD   e_sp;                        // Initial SP value
		WORD   e_csum;                      // Checksum
		WORD   e_ip;                        // Initial IP value
		WORD   e_cs;                        // Initial (relative) CS value
		WORD   e_lfarlc;                    // File address of relocation table
		WORD   e_ovno;                      // Overlay number
		WORD   e_res[4];                    // Reserved words
		WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
		WORD   e_oeminfo;                   // OEM information; e_oemid specific
		WORD   e_res2[10];                  // Reserved words
		LONG   e_lfanew;                    // File address of new exe header
	} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

	typedef struct _IMAGE_DATA_DIRECTORY {
		DWORD   VirtualAddress;
		DWORD   Size;
	} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;



	typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD        Magic;
		BYTE        MajorLinkerVersion;
		BYTE        MinorLinkerVersion;
		DWORD       SizeOfCode;
		DWORD       SizeOfInitializedData;
		DWORD       SizeOfUninitializedData;
		DWORD       AddressOfEntryPoint;
		DWORD       BaseOfCode;
		ULONGLONG   ImageBase;
		DWORD       SectionAlignment;
		DWORD       FileAlignment;
		WORD        MajorOperatingSystemVersion;
		WORD        MinorOperatingSystemVersion;
		WORD        MajorImageVersion;
		WORD        MinorImageVersion;
		WORD        MajorSubsystemVersion;
		WORD        MinorSubsystemVersion;
		DWORD       Win32VersionValue;
		DWORD       SizeOfImage;
		DWORD       SizeOfHeaders;
		DWORD       CheckSum;
		WORD        Subsystem;
		WORD        DllCharacteristics;
		ULONGLONG   SizeOfStackReserve;
		ULONGLONG   SizeOfStackCommit;
		ULONGLONG   SizeOfHeapReserve;
		ULONGLONG   SizeOfHeapCommit;
		DWORD       LoaderFlags;
		DWORD       NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

	typedef struct _IMAGE_FILE_HEADER {
		WORD    Machine;
		WORD    NumberOfSections;
		DWORD   TimeDateStamp;
		DWORD   PointerToSymbolTable;
		DWORD   NumberOfSymbols;
		WORD    SizeOfOptionalHeader;
		WORD    Characteristics;
	} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

	typedef struct _IMAGE_NT_HEADERS64 {
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

	typedef struct _IMAGE_EXPORT_DIRECTORY {
		DWORD   Characteristics;
		DWORD   TimeDateStamp;
		WORD    MajorVersion;
		WORD    MinorVersion;
		DWORD   Name;
		DWORD   Base;
		DWORD   NumberOfFunctions;
		DWORD   NumberOfNames;
		DWORD   AddressOfFunctions;     // RVA from base of image
		DWORD   AddressOfNames;         // RVA from base of image
		DWORD   AddressOfNameOrdinals;  // RVA from base of image
	} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

	typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;

#pragma endregion

	namespace utils
	{
		static constexpr unsigned int crc_table[256] =
		{
   0x00000000U, 0x77073096U, 0xEE0E612CU, 0x990951BAU, 0x076DC419U,
	  0x706AF48FU, 0xE963A535U, 0x9E6495A3U, 0x0EDB8832U, 0x79DCB8A4U,
	  0xE0D5E91EU, 0x97D2D988U, 0x09B64C2BU, 0x7EB17CBDU, 0xE7B82D07U,
	  0x90BF1D91U, 0x1DB71064U, 0x6AB020F2U, 0xF3B97148U, 0x84BE41DEU,
	  0x1ADAD47DU, 0x6DDDE4EBU, 0xF4D4B551U, 0x83D385C7U, 0x136C9856U,
	  0x646BA8C0U, 0xFD62F97AU, 0x8A65C9ECU, 0x14015C4FU, 0x63066CD9U,
	  0xFA0F3D63U, 0x8D080DF5U, 0x3B6E20C8U, 0x4C69105EU, 0xD56041E4U,
	  0xA2677172U, 0x3C03E4D1U, 0x4B04D447U, 0xD20D85FDU, 0xA50AB56BU,
	  0x35B5A8FAU, 0x42B2986CU, 0xDBBBC9D6U, 0xACBCF940U, 0x32D86CE3U,
	  0x45DF5C75U, 0xDCD60DCFU, 0xABD13D59U, 0x26D930ACU, 0x51DE003AU,
	  0xC8D75180U, 0xBFD06116U, 0x21B4F4B5U, 0x56B3C423U, 0xCFBA9599U,
	  0xB8BDA50FU, 0x2802B89EU, 0x5F058808U, 0xC60CD9B2U, 0xB10BE924U,
	  0x2F6F7C87U, 0x58684C11U, 0xC1611DABU, 0xB6662D3DU, 0x76DC4190U,
	  0x01DB7106U, 0x98D220BCU, 0xEFD5102AU, 0x71B18589U, 0x06B6B51FU,
	  0x9FBFE4A5U, 0xE8B8D433U, 0x7807C9A2U, 0x0F00F934U, 0x9609A88EU,
	  0xE10E9818U, 0x7F6A0DBBU, 0x086D3D2DU, 0x91646C97U, 0xE6635C01U,
	  0x6B6B51F4U, 0x1C6C6162U, 0x856530D8U, 0xF262004EU, 0x6C0695EDU,
	  0x1B01A57BU, 0x8208F4C1U, 0xF50FC457U, 0x65B0D9C6U, 0x12B7E950U,
	  0x8BBEB8EAU, 0xFCB9887CU, 0x62DD1DDFU, 0x15DA2D49U, 0x8CD37CF3U,
	  0xFBD44C65U, 0x4DB26158U, 0x3AB551CEU, 0xA3BC0074U, 0xD4BB30E2U,
	  0x4ADFA541U, 0x3DD895D7U, 0xA4D1C46DU, 0xD3D6F4FBU, 0x4369E96AU,
	  0x346ED9FCU, 0xAD678846U, 0xDA60B8D0U, 0x44042D73U, 0x33031DE5U,
	  0xAA0A4C5FU, 0xDD0D7CC9U, 0x5005713CU, 0x270241AAU, 0xBE0B1010U,
	  0xC90C2086U, 0x5768B525U, 0x206F85B3U, 0xB966D409U, 0xCE61E49FU,
	  0x5EDEF90EU, 0x29D9C998U, 0xB0D09822U, 0xC7D7A8B4U, 0x59B33D17U,
	  0x2EB40D81U, 0xB7BD5C3BU, 0xC0BA6CADU, 0xEDB88320U, 0x9ABFB3B6U,
	  0x03B6E20CU, 0x74B1D29AU, 0xEAD54739U, 0x9DD277AFU, 0x04DB2615U,
	  0x73DC1683U, 0xE3630B12U, 0x94643B84U, 0x0D6D6A3EU, 0x7A6A5AA8U,
	  0xE40ECF0BU, 0x9309FF9DU, 0x0A00AE27U, 0x7D079EB1U, 0xF00F9344U,
	  0x8708A3D2U, 0x1E01F268U, 0x6906C2FEU, 0xF762575DU, 0x806567CBU,
	  0x196C3671U, 0x6E6B06E7U, 0xFED41B76U, 0x89D32BE0U, 0x10DA7A5AU,
	  0x67DD4ACCU, 0xF9B9DF6FU, 0x8EBEEFF9U, 0x17B7BE43U, 0x60B08ED5U,
	  0xD6D6A3E8U, 0xA1D1937EU, 0x38D8C2C4U, 0x4FDFF252U, 0xD1BB67F1U,
	  0xA6BC5767U, 0x3FB506DDU, 0x48B2364BU, 0xD80D2BDAU, 0xAF0A1B4CU,
	  0x36034AF6U, 0x41047A60U, 0xDF60EFC3U, 0xA867DF55U, 0x316E8EEFU,
	  0x4669BE79U, 0xCB61B38CU, 0xBC66831AU, 0x256FD2A0U, 0x5268E236U,
	  0xCC0C7795U, 0xBB0B4703U, 0x220216B9U, 0x5505262FU, 0xC5BA3BBEU,
	  0xB2BD0B28U, 0x2BB45A92U, 0x5CB36A04U, 0xC2D7FFA7U, 0xB5D0CF31U,
	  0x2CD99E8BU, 0x5BDEAE1DU, 0x9B64C2B0U, 0xEC63F226U, 0x756AA39CU,
	  0x026D930AU, 0x9C0906A9U, 0xEB0E363FU, 0x72076785U, 0x05005713U,
	  0x95BF4A82U, 0xE2B87A14U, 0x7BB12BAEU, 0x0CB61B38U, 0x92D28E9BU,
	  0xE5D5BE0DU, 0x7CDCEFB7U, 0x0BDBDF21U, 0x86D3D2D4U, 0xF1D4E242U,
	  0x68DDB3F8U, 0x1FDA836EU, 0x81BE16CDU, 0xF6B9265BU, 0x6FB077E1U,
	  0x18B74777U, 0x88085AE6U, 0xFF0F6A70U, 0x66063BCAU, 0x11010B5CU,
	  0x8F659EFFU, 0xF862AE69U, 0x616BFFD3U, 0x166CCF45U, 0xA00AE278U,
	  0xD70DD2EEU, 0x4E048354U, 0x3903B3C2U, 0xA7672661U, 0xD06016F7U,
	  0x4969474DU, 0x3E6E77DBU, 0xAED16A4AU, 0xD9D65ADCU, 0x40DF0B66U,
	  0x37D83BF0U, 0xA9BCAE53U, 0xDEBB9EC5U, 0x47B2CF7FU, 0x30B5FFE9U,
	  0xBDBDF21CU, 0xCABAC28AU, 0x53B39330U, 0x24B4A3A6U, 0xBAD03605U,
			0xCDD70693U, 0x54DE5729U, 0x23D967BFU, 0xB3667A2EU, 0xC4614AB8U,
			0x5D681B02U, 0x2A6F2B94U, 0xB40BBE37U, 0xC30C8EA1U, 0x5A05DF1BU,
			0x2D02EF8DU
		};

		template<unsigned long long idx>
		constexpr unsigned int crc32(const wchar_t* str)
		{
			return (crc32<idx - 1>(str) >> 8) ^ crc_table[(crc32<idx - 1>(str) ^ str[idx]) & 0x000000FF];
		}

		template<>
		constexpr unsigned int crc32<unsigned long long(-1)>(const wchar_t* str)
		{
			return 0xFFFFFFFF;
		}

		__forceinline int to_lower(int _C)
		{
			auto result = _C;
			if (_C >= 'A' && _C <= 'Z')
				result += 32;

			return result;
		}

		__forceinline unsigned int str_length(const char* string)
		{
			unsigned long long idx = 0;

			while (string[idx] != L'\0')
				++idx;

			return idx;
		}

		__forceinline unsigned int str_length(const wchar_t* string)
		{
			unsigned long long idx = 0;

			while (string[idx] != L'\0')
				++idx;

			return idx;
		}

		__forceinline bool str_equals(const wchar_t* string, const wchar_t* string2)
		{
			for (unsigned int idx = 0; idx < _MIN(str_length(string), str_length(string2)); idx++)
			{
				if (to_lower(string[idx]) != to_lower(string2[idx]))
					return false;
			}

			return true;
		}

		__forceinline const wchar_t* str_widen(const char* string)
		{
			const auto len = str_length(string);
			wchar_t* result = new wchar_t[len];

			for (int idx = 0; idx < len; idx++)
				result[idx] = string[idx];

			return result;
		}

		__forceinline unsigned long long get_image_base_(const wchar_t* string)
		{
			const auto block = (PEB*)__readgsqword(0x60);
			if (!block)
				return 0;

			const auto begin = block->Ldr->InMemoryOrderModuleList.Flink;;
			auto image = begin;
			int count = 0;
			do
			{
				if (count++ > 64)
					break;

				auto entry = (LDR_DATA_TABLE_ENTRY*)((unsigned long long)(image) - sizeof(LIST_ENTRY));
				if (!entry)
					continue;

				const auto name = entry->BaseDllName.Buffer;
				if (!name)
					continue;
				 
				if (str_equals(name, string))
					return reinterpret_cast<unsigned long long>(entry->DllBase);

				image = (LIST_ENTRY*)(image)->Flink;
			} while (image != begin);

			return 0;
		}

		__forceinline unsigned long long get_function_addressex(const wchar_t* string, unsigned long long module_base)
		{
			const auto dos_header = PIMAGE_DOS_HEADER(module_base);
			const auto nt_headers = PIMAGE_NT_HEADERS(LPBYTE(module_base) + dos_header->e_lfanew);
			const auto data_dir = PIMAGE_DATA_DIRECTORY(nt_headers->OptionalHeader.DataDirectory);

			const auto virt_address = data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			if (!virt_address)
				return 0;

			const auto export_dir = PIMAGE_EXPORT_DIRECTORY(LPBYTE(module_base) + virt_address);

			const auto export_count = export_dir->NumberOfNames;
			if (!export_count)
				return 0;

			const auto function_addresses = PDWORD(LPBYTE(module_base) + export_dir->AddressOfFunctions);
			const auto name_addresses = PDWORD(LPBYTE(module_base) + export_dir->AddressOfNames);
			const auto name_ordinals = PWORD(LPBYTE(module_base) + export_dir->AddressOfNameOrdinals);

			for (int i = export_count; i != 0; i--)
			{
				const auto name = (const char*)(LPBYTE(module_base) + name_addresses[i - 1]);

				if (utils::str_equals(str_widen(name), string))
					return (unsigned long long)(LPVOID(LPBYTE(module_base) + function_addresses[name_ordinals[i - 1]]));
			};

			return 0;
		}

		// sometimes this function will return unwanted functions with the same name from other images.
		__forceinline unsigned long long get_function_address(const wchar_t* string)
		{
			const auto block = (PEB*)__readgsqword(0x60);
			if (!block)
				return 0;

			const auto begin = block->Ldr->InMemoryOrderModuleList.Flink;;
			auto image = begin;
			int count = 0;
			do
			{
				if (count++ > 64)
					break;

				auto entry = (LDR_DATA_TABLE_ENTRY*)((unsigned long long)(image) - sizeof(LIST_ENTRY));
				if (!entry)
					continue;

				const auto name = entry->BaseDllName.Buffer;
				if (!name)
					continue;

				const auto address = get_function_addressex(string, (unsigned long long)entry->DllBase);
				if (address)
					return address;

				image = (LIST_ENTRY*)(image)->Flink;
			} while (image != begin);

			return 0;
		}

		__forceinline unsigned long long get_image_base(const wchar_t* string)
		{
			auto base = get_image_base_(string);
			
#ifndef _ENO_WIN32_CALLS
			if (!base)
			{
				static auto load_library = reinterpret_cast<decltype(&LoadLibraryW)>(get_function_addressex(L"LoadLibraryW", get_image_base_(L"kernel32.dll")));

				if (!(base = (unsigned long long)load_library(string)))
					return 0;
			}
#endif // !_ENO_WIN32_CALLS

			return base;
		}
	}

	namespace types
	{
		template <typename t1, typename t2>
		struct pair_t
		{
			t1 key;
			t2 value;
		};

		template <typename t1, typename t2>
		class c_dict
		{
		public:

		private:
			pair_t<t1, t2>* data;
			unsigned int size = 0;
		public:
			__forceinline c_dict(unsigned int max_size = 1024) { data = new pair_t<t1, t2>[max_size] {}; }

			__forceinline void push_back(pair_t<t1, t2> entry)
			{
				data[size] = entry;
				size++;
			}

			__forceinline bool contains(t1 key)
			{
				for (unsigned int idx = 0; idx < size; idx++)
				{
					const auto& entry = data[idx];
					if (entry.key != key)
						continue;

					return true;
				}

				return false;
			}

			__forceinline t2 operator[](t1 key)
			{
				for (unsigned int idx = 0; idx < size; idx++)
				{
					const auto& entry = data[idx];
					if (entry.key != key)
						continue;

					return entry.value;
				}

				return t2();
			}
		};
	}

	__forceinline unsigned long long get_image_base_cached(const unsigned long image_name_hash, const wchar_t* image_name)
	{
		static auto images = types::c_dict<unsigned long, unsigned long long>();

		if (!images.contains(image_name_hash))
			images.push_back({ image_name_hash, utils::get_image_base(image_name) });

		return images[image_name_hash];
	}

	__forceinline unsigned long long get_function_addressex_cached(const unsigned long function_name_hash, const wchar_t* function_name, const wchar_t* image_name)
	{
		static auto images = types::c_dict<unsigned long, unsigned long long>();

		if (!images.contains(function_name_hash))
			images.push_back({ function_name_hash, utils::get_function_addressex(function_name, utils::get_image_base(image_name)) });

		return images[function_name_hash];
	}

	__forceinline unsigned long long get_function_address_cached(const unsigned long function_name_hash, const wchar_t* function_name)
	{
		static auto images = types::c_dict<unsigned long, unsigned long long>();

		if (!images.contains(function_name_hash))
			images.push_back({ function_name_hash, utils::get_function_address(function_name) });

		return images[function_name_hash];
	}
}

// creates a uint hash of a string during compilation
#define _EHASH_STRING(x) (easyimport::utils::crc32<sizeof(x) - 2>(x) ^ 0xFFFFFFFF)

// this is unstable as it relies on no duplicate functions existing, for a more 'safe' experience use '_EIMPORTEX'
#define _EIMPORT(function_name) reinterpret_cast<decltype(&function_name)>(easyimport::get_function_address_cached(_EHASH_STRING(L#function_name), L#function_name))

// if image is not loaded it will load that image via loadlibrary (you can disable this with _ENO_WIN32_CALLS
#define _EIMPORTEX(function_name, image_name) reinterpret_cast<decltype(&function_name)>(easyimport::get_function_addressex_cached(_EHASH_STRING(L#function_name), L#function_name, L##image_name))

// if image is not loaded it will load that image via loadlibrary (you can disable this with _ENO_WIN32_CALLS
#define _EIMAGE_BASE(image_name) easyimport::get_image_base_cached(_EHASH_STRING(L##image_name), L##image_name)
 
#endif // !_EASYIMPORT_HPP