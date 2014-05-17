/*
Author:	  Alexander Hanel
Date:	  5/17/2014
Purpose:    This is a pintool that logs all calls & branches to a file. 
Credit:	  A large portion of the code was inspired/copied from Robert Muth's 
		  pin/source/tools/SimpleExample/edgcnt.cpp. Thank you Intel for 
		  providing so many great examples. See bottom for example output.
		  Slow...
*/

#include <stdio.h>
#include "pin.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <map>
#include <string>
using namespace std;
extern "C" {
#include "xed-interface.h"
}

// Global Variables 
bool started = FALSE;   //  
ADDRINT logAddr = 0;    // 
ADDRINT addr;
vector<string> modules;
ofstream outFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "bc.txt", "specify output file name");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool prints the source & destinaton of control flow" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Log App has Started                                                   */
/* ===================================================================== */

VOID AppStart(VOID *v) 
{ 
    outFile << "[APP] Application Started" << endl;
} 

/* ===================================================================== */
/* White list addresses in loaded modules                                */
/* ===================================================================== */

VOID whiteListImage(IMG Img, VOID *v)
{ 
	if (IMG_IsMainExecutable(Img))
		outFile << "[IMG] Main Module" << endl; 
	else
		modules.push_back(IMG_Name(Img).c_str());

	// Add Module Details to the log
	outFile << "[IMG] Module Name: " << IMG_Name(Img).c_str() << endl;  
	outFile << "[IMG] Module Base: " << hex << IMG_LowAddress(Img) << endl;  
	outFile << "[IMG] Module End: "  << hex << IMG_HighAddress(Img) << endl;  
}

/* ===================================================================== */
/* Checks if ADDRINT value is within a module previously white listed	   */
/* in whiteListImage(IMG, VOID).								   */ 
/* Souce pin/source/tools/SimpleExamples/coco.cpp by Robert Muth	        */
/* ===================================================================== */

bool isAddressInModule(ADDRINT addr)
{
	IMG img = IMG_FindByAddress(addr);
	string path = (IMG_Valid(img) ? IMG_Name(img) : "InvalidImg");
	auto it = std::find(modules.begin(), modules.end(), path);
	if (it != modules.end())
		return TRUE;
	else
		return FALSE;
}

/* ===================================================================== */
/* Print the dissasembly. Source								   */
/*	 pin/source/tools/SimpleExamples/coco.cpp by Mark Charney		   */
/* ===================================================================== */

string getDism(ADDRINT pc) 
{
#if defined(TARGET_IA32E)
    static const xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate);
	const unsigned int max_inst_len = 15;

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(pc), max_inst_len);
	BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	if (xed_ok) 
	{
		char buf[2048];
		xed_uint64_t runtime_address = static_cast<xed_uint64_t>(pc); 

		xed_decoded_inst_dump_intel_format(&xedd, buf, 2048, runtime_address);
		return buf;
	}
	return "";
}

/* ===================================================================== */
/* White list addresses in loaded modules                                */
/* ===================================================================== */

void logSourceDest( ADDRINT source, ADDRINT dest, bool taken )
{
	if (!taken)
		return;
	outFile << "[INS] Src: " << hex << source << " Dism: " << getDism(source) << " Dest: " << hex << dest << endl;
}

/* ===================================================================== */
/* Main Instruction					                                 */
/* ===================================================================== */

/* NOTES
	* What data do I want to record: Source, Destination, Disassembly and Type 
*/

VOID Instruction( INS ins, void *v )
{
	//check for invalid INS
	if( !INS_Valid(ins) ) 
	{
		outFile << "error " << hex << INS_Address(ins);
		return;
	}
	if (isAddressInModule(INS_Address(ins)))
		return;
	if( INS_IsDirectBranchOrCall(ins) )
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) logSourceDest,  IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR , IARG_BRANCH_TAKEN, IARG_END);
		return;
	}
	else if( INS_IsIndirectBranchOrCall(ins) )
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) logSourceDest,  IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR , IARG_BRANCH_TAKEN, IARG_END);
		return; 
	}
	else if( INS_IsSyscall(ins) )
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) logSourceDest,  IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR , IARG_BRANCH_TAKEN, IARG_END);
		return; 
	}
	// Not a branch Instruction 
	return;
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) 
	   return Usage();
    // Creae Log file 
    outFile.open(KnobOutputFile.Value().c_str());
    // Register a notification function that is called after pin initialization is finished.
    PIN_AddApplicationStartFunction(AppStart,0);
    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(whiteListImage, 0);
    //  Add a function used to instrument at instruction granularity 
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    return 0;
}

/*
Example Output
------------------------------------------------------
[IMG] Main Module
[IMG] Module Name: c:\pin\upx.exe
[IMG] Module Base: 400000
[IMG] Module End: 589fff
[IMG] Module Name: C:\Windows\syswow64\KERNELBASE.dll
[IMG] Module Base: 75f20000
[IMG] Module End: 75f66fff
[IMG] Module Name: C:\Windows\syswow64\kernel32.dll
[IMG] Module Base: 765f0000
[IMG] Module End: 766fffff
[IMG] Module Name: C:\Windows\SysWOW64\ntdll.dll
[IMG] Module Base: 77de0000
[IMG] Module End: 77f5ffff
[APP] Application Started
[IMG] Module Name: C:\Windows\syswow64\msvcrt.dll
[IMG] Module Base: 75d80000
[IMG] Module End: 75e2bfff
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
[INS] Src: 58774b Dism: jnz 0x587748 Dest: 587748
....
*/