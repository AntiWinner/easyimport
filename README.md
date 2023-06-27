# easyimport
a seamless and dynamic function importing library with no use of crt or the requirement of any includes. 

## features
- no crt/win32 calls/includes required
- single header
- image and function address caching
- a **few** comments where needed
- lightweight and simple to use

## results
here's a brief example of what a simple messagebox will produce to a decompiler (with pdb)
### example usage
```c++
#include <Windows.h> 
#include "easyimport.hpp"

int main()
{
	// first call will initialize it and load any non-loaded libraries (user32 etc)
	_EIMPORTEX(MessageBoxA, "user32.dll")(0, "I'm a message box", "Wowww", 0);

	// second call will be **much** faster than the prior due to caching.
	_EIMPORTEX(MessageBoxA, "user32.dll")(0, "I'm a message box 2", "Crazyyy", 0);
	return 0;
}
```

### disassembled (with pdb)
```c
  v3 = easyimport::utils::crc32<20>(*(const wchar_t **)&argc);
  v4 = ~(easyimport::utils::crc_table[(unsigned __int8)(LOBYTE(easyimport::utils::crc_table[(unsigned __int8)(aIMAMessageBox[10] ^ v3)]) ^ BYTE1(v3) ^ aIMAMessageBox[12])] ^ ((easyimport::utils::crc_table[(unsigned __int8)(aIMAMessageBox[10] ^ v3)] ^ (v3 >> 8)) >> 8));
  v110 = v4;
  v5 = (_DWORD *)(*(_QWORD *)NtCurrentTeb()->Reserved1[11] + 4i64);
  if ( __TSS0__1__get_function_addressex_cached_easyimport__YA_KKPEB_W0_Z_4HA > *v5 )
  {
    Init_thread_header(&__TSS0__1__get_function_addressex_cached_easyimport__YA_KKPEB_W0_Z_4HA);
    if ( __TSS0__1__get_function_addressex_cached_easyimport__YA_KKPEB_W0_Z_4HA == -1 )
    {
      `easyimport::get_function_addressex_cached'::`2'::images = 0i64;
      v6 = operator new[](0x4000ui64);
      memset_0(v6, 0i64, 0x4000i64);
      *(_QWORD *)&`easyimport::get_function_addressex_cached'::`2'::images = v6;
      Init_thread_footer(&__TSS0__1__get_function_addressex_cached_easyimport__YA_KKPEB_W0_Z_4HA);
    }
    v4 = v110;
  }
...
```

##### for a full snippet view [decompiled.c](https://github.com/AntiWinner/easyimport/blob/main/decompiled.c)
