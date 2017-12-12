#include <windows.h>

void sleep(unsigned int mseconds)
{
	Sleep(mseconds * 1000);
}
