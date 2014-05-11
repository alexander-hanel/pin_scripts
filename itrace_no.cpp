/*
alexander hanel
log IP of all instructions that do not reside in a module. 
*/
#include <stdio.h> 
#include <iostream> 
#include "pin.H" 
#include <string>
#include <algorithm>

bool started = FALSE;
ADDRINT addr;
vector<string> modules;

FILE * trace;

// This function is called before every instruction is executed
// and prints the IP
VOID printip(VOID *ip) { fprintf(trace, "%p\n", ip); }

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
	IMG img = IMG_FindByAddress(INS_Address(ins));
	string path = (IMG_Valid(img) ? IMG_Name(img) : "InvalidImg");
	auto it = std::find(modules.begin(), modules.end(), path);
	if (it != modules.end())
		return;
	else
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);
}

VOID Image(IMG Img, VOID *v)
{ 
	if (IMG_IsMainExecutable(Img))
		printf("Main module\n");
	else
		modules.push_back(IMG_Name(Img).c_str());
}

VOID AppStart(VOID *v) 
{ 
	printf("whitelist created!\n"); 
	started = TRUE;
} 

VOID Fini(INT32 code, VOID *v) 
{ 
	printf("Instrumentation has completed!\n");
	int ii;
	for (ii = 0; ii < modules.size(); ii++)
	{
		cout << modules[ii] << endl;
	}
} 

INT32 Usage() 
{ 
	return -1; 
}

int main(int argc, char * argv[]) 
{ 
	trace = fopen("itrace.out", "w");
	if (PIN_Init(argc, argv)) 
		return Usage();
	// is called after loader is completed
	PIN_AddApplicationStartFunction(AppStart,0); 
	// is called every time an image loads 
	IMG_AddInstrumentFunction(Image, 0);
	INS_AddInstrumentFunction(Instruction, 0); 
	// TRACE_AddInstrumentFunction(Trace, 0);
	PIN_AddFiniFunction(Fini, 0); 
	PIN_StartProgram(); 
	return 0; 
}
