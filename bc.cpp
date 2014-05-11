/*
alexander hanel 5/10/2014
In progress example of logging all branches and calls. While ignoring code 
in loaded modules.
*/

#include <stdio.h> 
#include "pin.H"
#include <iostream>
#include <algorithm>
#include <map>
#include <string>
using namespace std;

/////////////////////////////////////////////////////////////////////////////////////

typedef enum
{
    ETYPE_INVALID,
    ETYPE_CALL,
    ETYPE_ICALL,
    ETYPE_BRANCH,
    ETYPE_IBRANCH,
    ETYPE_RETURN,
    ETYPE_SYSCALL,
    ETYPE_LAST
}ETYPE;

FILE * trace;
bool started = FALSE;
ADDRINT logAddr = 0;
ADDRINT addr;
vector<string> modules;

/////////////////////////////////////////////////////////////////////////////////////

string StringFromEtype( ETYPE etype)
{
    switch(etype)
    {
      case ETYPE_CALL:
        return "C";
      case ETYPE_ICALL:
        return "c";
      case ETYPE_BRANCH:
        return "B";
      case ETYPE_IBRANCH:
        return "b";
      case ETYPE_RETURN:
        return "r";
      case ETYPE_SYSCALL:
        return "s";
      default:
        ASSERTX(0);
        return "INVALID";
    }
}

VOID PrintIp(VOID *source, VOID *dest)
{
    fprintf(trace, "Source %p, Dest %p", source, dest);
    fflush(trace);
}

bool IsAddressInModule(ADDRINT addr)
{
	IMG img = IMG_FindByAddress(addr);
	string path = (IMG_Valid(img) ? IMG_Name(img) : "InvalidImg");
	auto it = std::find(modules.begin(), modules.end(), path);
	if (it != modules.end())
	{
		return TRUE;
	}
	else
	{
	    return FALSE;
	}
}

void IsSamePage(ADDRINT source, ADDRINT dest, bool taken)
{
    if (!taken)
    {
	   logAddr = 0;
	   return; 
    }

    fprintf(trace, "%x %x\n", source, dest);
    fflush(trace);
    return;
}

VOID Image(IMG Img, VOID *v)
{ 
	if (IMG_IsMainExecutable(Img))
		fprintf(trace, "Main module\n");
	else
		modules.push_back(IMG_Name(Img).c_str());

	fprintf(trace, "Loading module %s \n", IMG_Name(Img).c_str());  
     fprintf(trace, "Module Base: %08x \n", IMG_LowAddress(Img));  
     fprintf(trace, "Module end: %08x \n", IMG_HighAddress(Img));  
	fflush(trace); 
}
 
VOID Fini(INT32 code, VOID *v) 
{ 
	cout << "Instrumentation has completed!\n" << endl;
	int ii;
	for (ii = 0; ii < modules.size(); ii++)
	{
		cout << modules[ii] << endl;
	}
} 

VOID AppStart(VOID *v) 
{ 
    fprintf(trace, "STARTED\n");
} 

VOID Instruction(INS ins, void *v)
{
    if (!INS_Valid(ins)) 
    {
	   fprintf(trace, "error %x", INS_Address(ins) );
	   return;
    }
    //if( INS_IsRet(ins) )
    //{
	   //// check if the return destination is in a module and 
	   //if (IsAddressInModule(INS_Address(ins)) == FALSE && IsAddressInModule(IARG_BRANCH_TARGET_ADDR) == TRUE)
		  //return;
	   //// check if far return is in different page 
	   //if (IsSamePage(ins, IARG_BRANCH_TARGET_ADDR))
		  //return; 
	   //// PRINT EDIT ME!!
    //    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) PrintIp, IARG_BRANCH_TARGET_ADDR,  IARG_END);

    //}

    // filter out addresses in modules 
    if (IsAddressInModule(INS_Address(ins)))
			 return;
    // check for syscalls 
    else if( INS_IsSyscall(ins) )
    {
	   return;
    }
    // check if is direct branh or call 
    else if (INS_IsDirectBranchOrCall(ins))
    {
	    if( INS_IsCall(ins) )
	    {
		  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)IsSamePage, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR , IARG_BRANCH_TAKEN, IARG_END);
		  if (logAddr == 0)
			 return;
		  if (IsAddressInModule(logAddr))
			 return;
		   // PRINT EDIT ME!!
		  //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) PrintIp, IARG_INST_PTR,  INS_DirectBranchOrCallTargetAddress(ins),IARG_END);
		  
	   }
        else
	   {
		  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) IsSamePage, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
		  if (logAddr == 0)
			 return;
		  if (IsAddressInModule(logAddr))
			 return;
		  // PRINT EDIT ME!!
            //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) PrintIp, IARG_INST_PTR, INS_DirectBranchOrCallTargetAddress(ins),  IARG_END);
	   }
    }
    else if( INS_IsIndirectBranchOrCall(ins) )
    {
        if( INS_IsCall(ins) )
	   {
		  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) IsSamePage, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
		  if (logAddr == 0)
			 return;
		  if (IsAddressInModule(logAddr))
			 return;
		  // PRINT EDIT ME!!
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) PrintIp, IARG_INST_PTR, logAddr,  IARG_END); 
	   }
        else
		  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) IsSamePage, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
		  if (logAddr == 0)
			 return;
		  if (IsAddressInModule(logAddr))
			 return;
		  // PRINT EDIT ME!!
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) PrintIp, IARG_INST_PTR, logAddr,  IARG_END);
    }
}

INT32 Usage()
{
    PIN_ERROR("This Pintool does some stuff..." 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    trace = fopen("profiler.txt", "w");
    PIN_AddApplicationStartFunction(AppStart,0);
    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}


