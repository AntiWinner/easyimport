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
