// injector-2.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>

#include <iostream>
#include <string>

using namespace std;

//  Forward declarations:
BOOL GetProcessList( );
BOOL ListProcessModules( DWORD dwPID );
BOOL ListProcessThreads( DWORD dwOwnerPID );
void printError( TCHAR* msg );

PIMAGE_IMPORT_DESCRIPTOR getImportTable( );
void PatchImportAddressTable( );

int _tmain(int argc, _TCHAR* argv[])
{
	/*int pid;
	cin >> pid;
	GetProcessList( );*/
	PatchImportAddressTable();
	return 0;
}

PIMAGE_IMPORT_DESCRIPTOR getImportTable(PBYTE baseAddr) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER) baseAddr;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(baseAddr + (DWORD) dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER32 optionalHeader = ntHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY dataDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR importTable = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddr + dataDirectory.VirtualAddress);

	//printf("dosHeader magic: %x\n", dosHeader->e_magic);
	//printf("ntHeader signature: %s\n", &(ntHeader->Signature)); // should be PE
	//printf("optionalHeader magic: %x\n", optionalHeader.Magic); // should be 0x10b
	//printf("dataDirectory (size): %x\n", dataDirectory.Size);
	//printf("dataDirectory (relative virtual addr): %x\n", dataDirectory.VirtualAddress);
	//printf("import table: %x\n", importTable);

	return importTable;
}


PROC CloseHandleOriginal;

void WINAPI CloseHandleEvil(_In_ HANDLE h) {
	printf("closing handle %x with %x", h, CloseHandleOriginal);
	((VOID(WINAPI *)(_In_ HANDLE)) CloseHandleOriginal)(h);
}

void PatchImportAddressTable()
{
	

	CHAR targetDllName[] = "KERNEL32.dll";
	SIZE_T targetDllNameLength = strlen(targetDllName);
	CHAR * targetFunctionNames[] = {"CloseHandle"};
	PROC hook = (PROC) CloseHandleEvil;

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
	IMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
	PIMAGE_THUNK_DATA currentThunk;
	PIMAGE_THUNK_DATA currentOriginalThunk;
	DWORD currentFuncAddress;
	PIMAGE_IMPORT_BY_NAME pOriginalFuncData;

	PBYTE baseAddr = (PBYTE) GetModuleHandle(NULL);
	pImageImportDescriptor = getImportTable(baseAddr);
	
	char *currentDllName;
	for (int i = 0; pImageImportDescriptor[i].Characteristics; ++i) {
		imageImportDescriptor = pImageImportDescriptor[i];

		currentDllName = (char *)(baseAddr + imageImportDescriptor.Name);
		//printf("%s\n", currentDllName);

		if (0 == strncmp(currentDllName, targetDllName, targetDllNameLength)) {
			
			currentThunk = (PIMAGE_THUNK_DATA) (baseAddr + imageImportDescriptor.FirstThunk);
			currentOriginalThunk = (PIMAGE_THUNK_DATA) (baseAddr + imageImportDescriptor.OriginalFirstThunk);
			
			while (currentOriginalThunk->u1.Function) {
				pOriginalFuncData = (PIMAGE_IMPORT_BY_NAME)(baseAddr + currentOriginalThunk->u1.Function);
				currentFuncAddress = (DWORD)(currentThunk->u1.AddressOfData);

				if(0 == strncmp(pOriginalFuncData->Name, targetFunctionNames[0], strlen(targetFunctionNames[0]))) {
					CloseHandleOriginal = (PROC) currentFuncAddress;
					currentThunk->u1.AddressOfData = (DWORD) CloseHandleEvil;
					/*printf("bingo!\n");
					
					printf("%x\n", currentOriginalThunk);
					printf("%x\n", currentThunk);
					printf("original: %s (%x)\n", pOriginalFuncData->Name, pOriginalFuncData->Hint);
					printf("normal: (%x)\n", currentFuncAddress);
					printf("normal: (%x)\n", GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle"));*/
				}

				currentOriginalThunk++;
				currentThunk++;
			}
		}
		pImageImportDescriptor++;
	}

	CloseHandle(OpenProcess(0, FALSE, GetCurrentProcessId()));
	printf("DONE.");
}

BOOL GetProcessList( )
{
  HANDLE hProcessSnap;
  HANDLE hProcess;
  PROCESSENTRY32 pe32;
  DWORD dwPriorityClass;

  // Take a snapshot of all processes in the system.
  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    printError( TEXT("CreateToolhelp32Snapshot (of processes)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( PROCESSENTRY32 );

  // Retrieve information about the first process,
  // and exit if unsuccessful
  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    printError( TEXT("Process32First") ); // show cause of failure
    CloseHandle( hProcessSnap );          // clean the snapshot object
    return( FALSE );
  }
  int pid = GetCurrentProcessId();

  // Now walk the snapshot of processes, and
  // display information about each process in turn
  do
  {
    _tprintf( TEXT("\n\n=====================================================" ));
    _tprintf( TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile );
    _tprintf( TEXT("\n-------------------------------------------------------" ));

    // Retrieve the priority class.
    dwPriorityClass = 0;
    hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
    if( hProcess == NULL )
      printError( TEXT("OpenProcess") );
    else
    {
      dwPriorityClass = GetPriorityClass( hProcess );
      if( !dwPriorityClass )
        printError( TEXT("GetPriorityClass") );
      CloseHandle( hProcess );
    }

    _tprintf( TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID );
    _tprintf( TEXT("\n  Thread count      = %d"),   pe32.cntThreads );
    _tprintf( TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID );
    _tprintf( TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase );
    if( dwPriorityClass )
      _tprintf( TEXT("\n  Priority class    = %d"), dwPriorityClass );

    // List the modules and threads associated with this process
    ListProcessModules( pe32.th32ProcessID );
    ListProcessThreads( pe32.th32ProcessID );

  } while( Process32Next( hProcessSnap, &pe32 ) );

  CloseHandle( hProcessSnap );
  return( TRUE );
}

BOOL ListProcessModules( DWORD dwPID )
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
  MODULEENTRY32 me32;

  // Take a snapshot of all modules in the specified process.
  hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, dwPID );
  if( hModuleSnap == INVALID_HANDLE_VALUE )
  {
    printError( TEXT("CreateToolhelp32Snapshot (of modules)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  me32.dwSize = sizeof( MODULEENTRY32 );

  // Retrieve information about the first module,
  // and exit if unsuccessful
  if( !Module32First( hModuleSnap, &me32 ) )
  {
    printError( TEXT("Module32First") );  // show cause of failure
    CloseHandle( hModuleSnap );           // clean the snapshot object
    return( FALSE );
  }

  // Now walk the module list of the process,
  // and display information about each module
  do
  {
    _tprintf( TEXT("\n\n     MODULE NAME:     %s"),   me32.szModule );
    _tprintf( TEXT("\n     Executable     = %s"),     me32.szExePath );
    _tprintf( TEXT("\n     Process ID     = 0x%08X"),         me32.th32ProcessID );
    _tprintf( TEXT("\n     Ref count (g)  = 0x%04X"),     me32.GlblcntUsage );
    _tprintf( TEXT("\n     Ref count (p)  = 0x%04X"),     me32.ProccntUsage );
    _tprintf( TEXT("\n     Base address   = 0x%08X"), (DWORD) me32.modBaseAddr );
    _tprintf( TEXT("\n     Base size      = %d"),             me32.modBaseSize );

  } while( Module32Next( hModuleSnap, &me32 ) );

  CloseHandle( hModuleSnap );
  return( TRUE );
}

BOOL ListProcessThreads( DWORD dwOwnerPID ) 
{ 
  HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
  THREADENTRY32 te32; 
 
  // Take a snapshot of all running threads  
  hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
  if( hThreadSnap == INVALID_HANDLE_VALUE ) 
    return( FALSE ); 
 
  // Fill in the size of the structure before using it. 
  te32.dwSize = sizeof(THREADENTRY32); 
 
  // Retrieve information about the first thread,
  // and exit if unsuccessful
  if( !Thread32First( hThreadSnap, &te32 ) ) 
  {
    printError( TEXT("Thread32First") ); // show cause of failure
    CloseHandle( hThreadSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the thread list of the system,
  // and display information about each thread
  // associated with the specified process
  do 
  { 
    if( te32.th32OwnerProcessID == dwOwnerPID )
    {
      _tprintf( TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID ); 
      _tprintf( TEXT("\n     Base priority  = %d"), te32.tpBasePri ); 
      _tprintf( TEXT("\n     Delta priority = %d"), te32.tpDeltaPri ); 
      _tprintf( TEXT("\n"));
    }
  } while( Thread32Next(hThreadSnap, &te32 ) ); 

  CloseHandle( hThreadSnap );
  return( TRUE );
}

void printError( TCHAR* msg )
{
  DWORD eNum;
  TCHAR sysMsg[256];
  TCHAR* p;

  eNum = GetLastError( );
  FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
         NULL, eNum,
         MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
         sysMsg, 256, NULL );

  // Trim the end of the line and terminate it with a null
  p = sysMsg;
  while( ( *p > 31 ) || ( *p == 9 ) )
    ++p;
  do { *p-- = 0; } while( ( p >= sysMsg ) &&
                          ( ( *p == '.' ) || ( *p < 33 ) ) );

  // Display the message
  _tprintf( TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg );
}