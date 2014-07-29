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
bool isAddressInModule(ADDRINT);

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
    started = TRUE;
} 


/* ===================================================================== */
/* Kill/Exit Process and Analysis	                                      */
/* ===================================================================== */
VOID EndAnalysis(ADDRINT addr)
{
	PIN_LockClient();
	if (isAddressInModule(addr) == FALSE)
	{
		outFile << "[END] " << hex << addr << endl;
		PIN_ExitApplication(0);	
	}
	PIN_UnlockClient();
}

/* ===================================================================== */
/* White list addresses in loaded modules                                */
/* ===================================================================== */

VOID whiteListImage(IMG Img, VOID *v)
{ 
	if (IMG_IsMainExecutable(Img))
	{
		outFile << "[IMG] Main Module" << endl; 
		outFile << "[IMG] Module Name: " << IMG_Name(Img).c_str() << endl;  
		outFile << "[IMG] Module Base: " << hex << IMG_LowAddress(Img) << endl;
		outFile << "[IMG] Module End: "  << hex << IMG_HighAddress(Img) << endl;
	}
	else
		modules.push_back(IMG_Name(Img).c_str());

	// Add Module Details to the log
	//outFile << "[IMG] Module Name: " << IMG_Name(Img).c_str() << endl;  
	//outFile << "[IMG] Module Base: " << hex << IMG_LowAddress(Img) << endl;  
	//outFile << "[IMG] Module End: "  << hex << IMG_HighAddress(Img) << endl;  

	// BP on GetStartupInfoA
	RTN rtn = RTN_FindByName(Img, "GetStartupInfoA");	
	if ( RTN_Valid( rtn ))
     {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(EndAnalysis), IARG_RETURN_IP, IARG_END);
        RTN_Close(rtn);
     }

	RTN rtn1 = RTN_FindByName(Img, "MessageBoxA");	
	if ( RTN_Valid( rtn1 ))
     {
        RTN_Open(rtn1);
        RTN_InsertCall(rtn1, IPOINT_BEFORE, AFUNPTR(EndAnalysis), IARG_RETURN_IP, IARG_END);
        RTN_Close(rtn1);
     }

	RTN rtn2 = RTN_FindByName(Img, "MessageBoxW");	
	if ( RTN_Valid( rtn2 ))
     {
        RTN_Open(rtn2);
        RTN_InsertCall(rtn2, IPOINT_BEFORE, AFUNPTR(EndAnalysis), IARG_RETURN_IP, IARG_END);
        RTN_Close(rtn2);
     }
	

	RTN rtn3 = RTN_FindByName(Img, "CreateProcessA");	
	if ( RTN_Valid( rtn3 ))
     {
        RTN_Open(rtn3);
        RTN_InsertCall(rtn3, IPOINT_BEFORE, AFUNPTR(EndAnalysis), IARG_RETURN_IP, IARG_END);
        RTN_Close(rtn3);
     }

}

/* ===================================================================== */
/* Checks if ADDRINT value is within a module previously white listed	   */
/* in whiteListImage(IMG, VOID).								   */ 
/* Souce pin/source/tools/SimpleExamples/coco.cpp by Robert Muth	        */
/* ===================================================================== */

bool isAddressInModule(ADDRINT addr)
{
	PIN_LockClient();
	IMG img = IMG_FindByAddress(addr);
	string path = (IMG_Valid(img) ? IMG_Name(img) : "InvalidImg");
	auto it = std::find(modules.begin(), modules.end(), path);
	if (it != modules.end())
	{	
		PIN_UnlockClient();
		return TRUE;
	}
	else
	{
		PIN_UnlockClient();
		return FALSE;
	}
	
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
	if (isAddressInModule(dest))
		return;
	if ( ( source & 0xffff0000 ) != ( dest & 0xffff0000 ) )
		outFile << "[INS] Src: " << "0x" << hex << source << " ;" << " Dism: " << getDism(source) << ';' << " Dest: " << "0x" << hex << dest << endl;
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
    PIN_InitSymbols();
    // Create Log file
    string output = string(argv[8]) + ".log" ;
    KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", output, "specify output file name");
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