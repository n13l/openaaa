#include <windows.h>
#include <wingdi.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
	
void
win32_console_init(void)
{
	if (!AttachConsole(ATTACH_PARENT_PROCESS))
		AllocConsole();

	freopen("conout$", "w", stdout);
	freopen("conerr$", "w", stderr);
}

void
win32_io_init(void)
{
	int hConHandle;
	long lStdHandle;

	if (!AttachConsole (ATTACH_PARENT_PROCESS))
		return;

	lStdHandle = (long)GetStdHandle(STD_OUTPUT_HANDLE);
	hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
	FILE *fp = _fdopen( hConHandle, "w" );
	*stdout = *fp;
	setvbuf( stdout, NULL, _IONBF, 0 );

	lStdHandle = (long)GetStdHandle(STD_INPUT_HANDLE);
	hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
	fp = _fdopen( hConHandle, "r" );
	*stdin = *fp;
	setvbuf( stdin, NULL, _IONBF, 0 );
	lStdHandle = (long)GetStdHandle(STD_ERROR_HANDLE);
	hConHandle = _open_osfhandle(lStdHandle, _O_TEXT);
	fp = _fdopen( hConHandle, "w" );
	*stderr = *fp;
	setvbuf( stderr, NULL, _IONBF, 0 );
}

__attribute__((constructor)) 
static void 
win32_io_ctor(void) 
{
	win32_io_init();
}
