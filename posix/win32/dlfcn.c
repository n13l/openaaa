#include <windows.h>
#include <process.h>
#include <psapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/compiler.h>
#include <mem/alloc.h>
#include <posix/list.h>

#include "dlfcn.h"

struct module {
	struct node n;
	HMODULE handle;
};

typedef struct global_object {
	HMODULE hModule;
	struct global_object *previous;
	struct global_object *next;
} global_object;

static global_object first_object;

static global_object *
global_search(HMODULE module)
{
	global_object *pobject;

	if (module == NULL)
		return NULL;

	for (pobject = &first_object; pobject ; pobject = pobject->next)
		if( pobject->hModule == module)
			return pobject;

	return NULL;
}

static void 
global_add(HMODULE module)
{
    global_object *pobject;
    global_object *nobject;

    if (module == NULL)
        return;

    pobject = global_search(module);
    /* Do not add object again if it's already on the list */
    if(pobject)
        return;

    for (pobject = &first_object; pobject->next ; pobject = pobject->next);

    nobject = malloc( sizeof(global_object) );

    if( !nobject )
        return;

    pobject->next = nobject;
    nobject->next = NULL;
    nobject->previous = pobject;
    nobject->hModule = module;
}

static void
global_rem(HMODULE module)
{
    global_object *pobject;

    if (module == NULL )
        return;

    pobject = global_search(module);

    if (!pobject)
        return;

    if (pobject->next)
        pobject->next->previous = pobject->previous;

    if (pobject->previous)
        pobject->previous->next = pobject->next;

    free(pobject);
}

static char error_buffer[65535];
static char *current_error;

static int
copy_string(char *dest, int dest_size, const char *src)
{
    int i = 0;

    /* gcc should optimize this out */
    if( !src || !dest )
        return 0;

    for (i = 0 ; i < dest_size-1 ; i++ ) {
        if (!src[i])
            break;
        else
            dest[i] = src[i];
    }

    dest[i] = '\0';

    return i;
}

static void
save_err_str(const char *str)
{
    DWORD dwMessageId;
    DWORD pos;

    dwMessageId = GetLastError( );

    if( dwMessageId == 0 )
        return;

    /* Format error message to:
     * "<argument to function that failed>": <Windows localized error message>
     */
    pos  = copy_string( error_buffer,     sizeof(error_buffer),     "\"" );
    pos += copy_string( error_buffer+pos, sizeof(error_buffer)-pos, str );
    pos += copy_string( error_buffer+pos, sizeof(error_buffer)-pos, "\": " );
    pos += FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwMessageId,
                          MAKELANGID( LANG_NEUTRAL, SUBLANG_DEFAULT ),
                          error_buffer+pos, sizeof(error_buffer)-pos, NULL );

    if( pos > 1 )
    {
        /* POSIX says the string must not have trailing <newline> */
        if( error_buffer[pos-2] == '\r' && error_buffer[pos-1] == '\n' )
            error_buffer[pos-2] = '\0';
    }

    current_error = error_buffer;
}

static void
save_err_ptr_str(const void *ptr)
{
	char ptr_buf[19]; 
	sprintf( ptr_buf, "0x%p", ptr);
	save_err_str( ptr_buf );
}

void
*dlopen(const char *file, int mode)
{
    HMODULE hModule;
    UINT uMode;

    current_error = NULL;

    /* Do not let Windows display the critical-error-handler message box */
    uMode = SetErrorMode(SEM_FAILCRITICALERRORS);

    if( file == 0 )
    {
        /* POSIX says that if the value of file is 0, a handle on a global
         * symbol object must be provided. That object must be able to access
         * all symbols from the original program file, and any objects loaded
         * with the RTLD_GLOBAL flag.
         * The return value from GetModuleHandle( ) allows us to retrieve
         * symbols only from the original program file. For objects loaded with
         * the RTLD_GLOBAL flag, we create our own list later on.
         */
        hModule = GetModuleHandle( NULL );

        if( !hModule )
            save_err_ptr_str( file );
    }
    else
    {
        char lpFileName[MAX_PATH];
        int i;

        /* MSDN says backslashes *must* be used instead of forward slashes. */
        for( i = 0 ; i < sizeof(lpFileName)-1 ; i++ )
        {
            if( !file[i] )
                break;
            else if( file[i] == '/' )
                lpFileName[i] = '\\';
            else
                lpFileName[i] = file[i];
        }
        lpFileName[i] = '\0';

        hModule = LoadLibraryEx( (LPSTR) lpFileName, NULL, 
                                 LOAD_WITH_ALTERED_SEARCH_PATH );

        if( !hModule )
            save_err_str( lpFileName );
        else if( (mode & RTLD_GLOBAL) )
            global_add(hModule);
    }

    /* Return to previous state of the error-mode bit flags. */
    SetErrorMode( uMode );

    return (void *) hModule;
}

int
dlclose(void *handle)
{
	HMODULE hModule = (HMODULE)handle;
	BOOL ret;

	current_error = NULL;

	ret = FreeLibrary(hModule);

	if (ret)
		global_rem( hModule );
	else
		save_err_ptr_str( handle );

	ret = !ret;
	return (int)ret;
}

void
*dlsym(void *handle, const char *name)
{
	FARPROC symbol;

	current_error = NULL;

	symbol = GetProcAddress(handle, name );
	if (symbol)
		goto exit;

        /* If the handle for the original program file is passed, also search
         * in all globally loaded objects.
         */

        HMODULE hModule = GetModuleHandle(NULL);
	symbol = GetProcAddress(hModule, name);
	if (symbol)
		goto exit;

	global_object *pobject;
	for(pobject = &first_object; pobject ; pobject = pobject->next) {
		if (!pobject->hModule)
			continue;

		symbol = GetProcAddress(pobject->hModule, name );
		if( symbol != NULL )
			break;
	}

exit:
	if( symbol == NULL )
		save_err_str(name);

	return (void*) symbol;
}

char
*dlerror(void)
{
	char *error_pointer = current_error;

	/* POSIX says that invoking dlerror( ) a second time, immediately 
	 * following a prior invocation, shall result in NULL being returned.
	 */

	current_error = NULL;
	return error_pointer;
}

int
dladdr(void *addr, Dl_info *info)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQuery(addr, &mbi, sizeof (mbi))) {
		save_err_str("VirtualQuery() failed!\n");
		return 0;
	}

	HMODULE module = (HMODULE)mbi.AllocationBase;
	char name[MAX_PATH];
	if (!GetModuleFileNameA(module, name, sizeof(name))) {
		save_err_str("GetModuleFileNameA() failed!");
		return 0;
	}

	strcpy((char *)info->dli_fname, name);

	info->dli_fbase = mbi.BaseAddress;
	info->dli_saddr = addr;

	strcpy((char *)info->dli_sname, name);
	return 1;
}

int
dl_iterate_phdr(int (*cb)(struct dl_phdr_info *info, size_t size, void *data), 
                void *data)
{
	unsigned long pid = GetCurrentProcessId();

	int mode = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
	HANDLE handle = OpenProcess(mode, 0, pid);
	if (handle == NULL)
		return 0;

	DWORD need = 0;
	if (!EnumProcessModules(handle, NULL, 0, &need))
		return 0;

	HMODULE *mods = alloca(need * sizeof(HMODULE));
	if (!EnumProcessModules(handle, mods, need, &need))
		return 0;

	char file[MAX_PATH] = {0};
	for (unsigned int i = 0; i < (need / sizeof(HMODULE)); i++) {
		if (!GetModuleFileNameEx(handle, mods[i], file, MAX_PATH - 1))
			continue;

		struct dl_phdr_info info = { 
			.dlpi_addr = mods[i],
			.dlpi_name = file
		};

		cb(&info, 0, data);
	}

	CloseHandle(handle);
	return 1;
}
