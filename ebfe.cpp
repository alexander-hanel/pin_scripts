/*
Author:		Alexander Hanel
Date:		07/13/2014
Purpose:	Packer profiler
*/

#include "pin.H"	
#include <iostream>
#include <fstream>
#include <algorithm>
#include <map>
#include <string>
using namespace std;
extern "C" {
#include "xed-interface.h"
}
namespace WINDOWS  
 {  
     #include <windows.h>  
 }  


bool started = FALSE;
ofstream outFile;
vector<string> modules;
UINT32 ins_count = 0;
UINT32 CountBreak = 0;
bool LogModules = FALSE;
bool LogBranches = FALSE;
bool thisIsTheEnd = FALSE;

KNOB<UINT32> KnobCountBreak(KNOB_MODE_WRITEONCE, "pintool", "count", "0", "what instruction to break on ");
KNOB<BOOL> KnobLogModule(KNOB_MODE_WRITEONCE, "pintool", "logm", "0", "log modules)");
KNOB<BOOL> KnobLogBranches(KNOB_MODE_WRITEONCE, "pintool", "logbc", "0", "log branches and calls)");


INT32 Usage()
{
	cerr << "This tool profiles packers." << endl;
	cerr << "\t-count : is an option to break on the count address." << endl;
	cerr << "\t-logm : log module addresses" << endl;
	cerr << "\t-logbc : log all branches and calls" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}



VOID AppStart( VOID *v )
{
	INT32 tem = 0;
	outFile << "[APP] Applicaation Started" << endl;
	started = TRUE;
}


VOID EBFE(CONTEXT * ctxt )
{

	/*
	Hex dump        Command                                
	90          NOP
	90          NOP
	90          NOP
	90          NOP
	90          NOP
	90          NOP
	60          PUSHAD
	31C0        XOR EAX,EAX
	83F8 00     CMP EAX,0
	74 02       JE SHORT 004014FA  ; possibly a branch was needed to have pin start another analysis
	90          NOP
	90          NOP
	90          NOP
	90          NOP
	61          POPAD
	EB FE       JMP SHORT 004014FD
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0, 0x83, 0xF8, 0x00, 0x74, 0x02, 0x90, 0x90, 0x90, 0x90, 0x61, 
	*/
	unsigned char sc[] = {
     0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0, 0x83, 0xF8, 0x00, 0x74, 0x02, 0x90, 0x90, 0x90, 0x90, 0x61,0xeb, 0xfe, 0x90, 0x90
	};

	VOID * mem = WINDOWS::VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	memcpy(mem, sc, sizeof(sc));
	outFile << "[EXIT] EB FE is Address " << hex << mem << endl;
	PIN_SetContextReg(ctxt,  REG_EIP, ADDRINT(mem));
	thisIsTheEnd = TRUE;
	PIN_ExecuteAt(ctxt);

}

VOID WhiteListImgAndSetHooks( IMG Img, VOID *v )
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
	outFile << "[IMG] Module Name: " << IMG_Name(Img).c_str() << endl;  
	outFile << "[IMG] Module Base: " << hex << IMG_LowAddress(Img) << endl;  
	outFile << "[IMG] Module End: "  << hex << IMG_HighAddress(Img) << endl; 
}

bool isAddressInModule(ADDRINT addr)
{
	if (LogModules == TRUE)
		return FALSE;
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

void logSourceDest( ADDRINT source, ADDRINT dest, bool taken, CONTEXT * ctxt )
{
	if (!taken)
		return;
	if (isAddressInModule(dest))
		return;
	if ( ( source & 0xffffffffffff0000 ) != ( dest & 0xffffffffffff0000 ) || LogBranches == TRUE )	
	{
		ins_count++;
		outFile << "[INS] Count " << dec << ins_count <<  " Src: " << "0x" << hex << source << " ;" << " Dism: " << getDism(source) << ';' << " Dest: " << "0x" << hex << dest << endl;
		if (ins_count == CountBreak )
		{
			thisIsTheEnd = TRUE;
			EBFE(ctxt);
		}
	}
	if (thisIsTheEnd)
	{
		outFile << "[EXIT] PIN_Detach() has been called" << endl;
		PIN_Detach(); 
	}

}

VOID Instruction( INS ins, void *v )
{
	//check for invalid INS
	if( !INS_Valid(ins) ) 
	{
		outFile << "Error at " << hex << INS_Address(ins);
		return;
	}
	// Ignore addresses in loaded modules 
	if (isAddressInModule(INS_Address(ins)))
		return;
	/*
	// Bypass VMware Detection 
	if (INS_Mnemonic(ins) == "IN")
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);
    */
	// On 32bit INS_InsertPredicatedCall does the same as INS_InsertCall
	// but on 64bit systems this call uses a feature of the processor. 
	if( INS_IsDirectBranchOrCall(ins) )
	{
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) logSourceDest,  IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR , IARG_BRANCH_TAKEN,  IARG_CONTEXT, IARG_END);
		return;
	}
	else if( INS_IsIndirectBranchOrCall(ins) )
	{
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) logSourceDest,  IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR , IARG_BRANCH_TAKEN, IARG_CONTEXT, IARG_END);
		return; 
	}
	else if( INS_IsSyscall(ins) )
	{
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) logSourceDest,  IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR , IARG_BRANCH_TAKEN, IARG_CONTEXT,IARG_END);
		return; 
	}
	// Not a branch Instruction 
	return;
}

VOID DetachCompleted(VOID *v)
{
	outFile << "Pin tool: detach is completed (in theory..) \n" << endl;
}

// Main
int main( int argc, char * argv[])
{
	if (PIN_Init(argc, argv))
		return Usage();
	// Pin Initialize Symbols
	PIN_InitSymbols();
	string output = string(argv[argc-1]) + ".log";
	KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", output, "specify output file name");
	outFile.open(KnobOutputFile.Value().c_str());
	// Register a notification function that is called after pin initialization is finished.
	PIN_AddApplicationStartFunction(AppStart,0);
	PIN_AddDetachFunction(DetachCompleted, 0);
	//  Register a call back to catch the loading of an image 
	IMG_AddInstrumentFunction(WhiteListImgAndSetHooks, 0);
	//  Add a function used to instrument at instruction granularity 
     INS_AddInstrumentFunction(Instruction, 0);
	// get arguments and set as global variables
	CountBreak = KnobCountBreak.Value();
	LogModules = KnobLogModule.Value();
	LogBranches = KnobLogBranches.Value();

	PIN_StartProgram();
}