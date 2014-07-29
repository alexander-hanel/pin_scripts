# Pin Tools#

### Summary ###

Hello. I had to drop this project because I have two Coursea classes coming up. The README includes the needed data I might need to pick up where I left off.

This is a collection of Pin tools that I wrote in C++.  The goal of this project was to learn C++ and Pin. My original idea was to create a Pin tool to profile packers. In it's most simplistic form a packer can be looked upon as some math (lossless decompression, decryption or obfuscation) and then a jump to the original entry point or the unpacked code. A pattern in packers is to write the unpacked code to another section or to an allocated block of memory. If only branch and call instructions with a source and destination to different memory pages are logged, then this can help with understanding the unpacking process. On most systems a memory page is 4096 bytes (section alignment is also usually the same size). Using Pin something similar to a call gate can be created to monitor all calls and branches to different memory pages. Below is the code to log all calls and branches. 
```
#!c++

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
```
Check if source and destination are in another page. 
```
#!c++
	if ( ( source & 0xfffffffffffff000 ) != ( dest & 0xfffffffffffff000 ) )	
	{
              stuff; 
	}
```
Example
```
#!text
[INS] Count 1 Src: 0x14f009 ; Dism: call 0x15008e; Dest: 0x15008e
[INS] Count 2 Src: 0x1500d6 ; Dism: ret 0x8; Dest: 0x143561
[INS] Count 3 Src: 0x14f009 ; Dism: call 0x15008e; Dest: 0x15008e
[INS] Count 4 Src: 0x1500d6 ; Dism: ret 0x8; Dest: 0x143561
[INS] Count 5 Src: 0x14f009 ; Dism: call 0x15008e; Dest: 0x15008e
[INS] Count 6 Src: 0x1500d6 ; Dism: ret 0x8; Dest: 0x143561
[INS] Count 7 Src: 0x14f009 ; Dism: call 0x15008e; Dest: 0x15008e
[INS] Count 8 Src: 0x1500d6 ; Dism: ret 0x8; Dest: 0x143561
[INS] Count 9 Src: 0x14f009 ; Dism: call 0x15008e; Dest: 0x15008e
```

In my testing I found having a page gate of 0xfff to be very loud. I eventually changed the size to be 0xffff to log less data. In order to test this out I decided to download the tuts4me unpack repo. This repo contains 1,415 sample. Six of the files could not be used due to being 64 bit or ARM. Since most of these executable are the same original packed code I decided to end execution/analysis when the sample called GetStartupInfoA, MessageBox* or CreateProcessA. To hook an API by name in the main function include PIN_InitSymbols(), then IMG_AddInstrumentFunction( func , 0) and the func will contain code similar to below. 
```
#!c++

RTN rtn = RTN_FindByName(Img, "GetStartupInfoA");	
if ( RTN_Valid( rtn ))
{
     RTN_Open(rtn);
     RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(EndAnalysis), IARG_RETURN_IP, IARG_END);
     RTN_Close(rtn);
}
```

The EndAnalysis function will contain code that is called once the API is invoked. For an example of it's usage check out this great [post](http://eindbazen.net/2013/04/pctf-2013-hypercomputer-1-bin-100/) on using RTN_FindByAddress & PIN_SetContextReg to bypass Sleep. Thanks to [@0vercl0k](https://twitter.com/0vercl0k) for sending me the link. Once I had all the files downloaded to a directory I created a Python script to execute all the sample using Pin. 

```
#!Python
import os 
import subprocess
import glob
import time 
paths = glob.glob("x\\*.exe")

for file_path in paths:
    log_name = str("y\\" + file_path[2:-3] + "error.log")
    print "processing %s" % file_path
    subprocess.call(["pin", "-logfile", log_name, "-t", "MyPintool.dll", "--", file_path])
    time.sleep(2)

```

A successful log would look something like this 

```
#!text
[IMG] Main Module
[IMG] Module Name: C:\pin\x\SEH Protector 2.5.0_Unpack ME.exe
[IMG] Module Base: 400000
[IMG] Module End: 529fff
[APP] Application Started
[INS] Src: 0x517991 ; Dism: jmp 0x4d0ba4; Dest: 0x4d0ba4
[INS] Src: 0x4d0baf ; Dism: call 0x407160; Dest: 0x407160
[INS] Src: 0x404e01 ; Dism: call esi; Dest: 0x4d0000
[INS] Src: 0x4d000d ; Dism: call 0x402cd0; Dest: 0x402cd0
[INS] Src: 0x402df4 ; Dism: ret ; Dest: 0x4d0012
[INS] Src: 0x4d003e ; Dism: call 0x403fa4; Dest: 0x403fa4
[INS] Src: 0x403fd2 ; Dism: ret ; Dest: 0x4d0043
[INS] Src: 0x4d004c ; Dism: call 0x404098; Dest: 0x404098
[INS] Src: 0x4040a1 ; Dism: ret ; Dest: 0x4d0051
[INS] Src: 0x4d006c ; Dism: call 0x4012e0; Dest: 0x4012e0
[INS] Src: 0x4d0076 ; Dism: call 0x4013b0; Dest: 0x4013b0
[END] 4013b
```
An unsuccessful log would look like this

```
#!text
[IMG] Main Module
[IMG] Module Name: C:\pin\x\UnPackMe_SPECb3.exe
[IMG] Module Base: 400000
[IMG] Module End: 407fff
[APP] Application Started
```
An easy way to test if the analysis was successful is to search for "[END]" in the logs. Out of 1,139 logs 730 contained the search end string. What sample did Pin or the packer error on?  

### Samples that Crashed (via the Windows Event Log) ###
```
#!text

unpackme_ntkrnl protector 0.15.h.exe  
unpackme_morphine2.7b.exe     
unpackme_mimoza 0.86.exe      
unpackme_marcrypt0.01.exe     
unpackme_hexalock copy protection 2.3.exe 
unpackme_ghf protector.c.exe       
unpackme_g!x protector 1.2.exe      
unpackme_expressor 1.6.0.1.g.exe       
unpackme_expressor 1.6.0.1.f.exe       
unpackme_expressor 1.6.0.1.e.exe       
unpackme_expressor 1.6.0.1.d.exe       
unpackme_expressor 1.6.0.1.c.exe       
unpackme_expressor 1.6.0.1.b.exe       
unpackme_expressor 1.6.0.1.a.exe       
unpackme_expressor 1.5.0.1.f.exe       
unpackme_expressor 1.5.0.1.e.exe       
unpackme_expressor 1.5.0.1.d.exe       
unpackme_expressor 1.5.0.1.c.exe       
unpackme_expressor 1.5.0.1.b.exe       
unpackme_expressor 1.5.0.1.a.exe       
unpackme_execryptor2.2.50.e.exe    
unpackme_execryptor2.2.50.d.exe     
unpackme_execryptor2.2.50.b.exe     
unpackme_execryptor2.1.20.f.exe     
unpackme_execryptor2.1.20.d.exe  
unpackme_execryptor2.1.20.b.exe   
unpackme_berio 1.02.exe 
unpackme_antidote 1.4.exe 
unpackme_acprotect2.0.2006.03.10.g1.exe    
unpackme_acprotect2.0.2006.03.10.f1.exe     
unpackme_acprotect2.0.2006.03.10.e1.exe   
unpackme_acprotect2.0.2006.03.10.d1.exe   
unpackme_acprotect2.0.2006.03.10.c1.exe   
unpackme_acprotect2.0.2006.03.10.b1.exe   
unpackme_acprotect2.0.2006.03.10.a1.exe   
unpackme_acprotect1.41.h1.exe     
unpackme_acprotect1.32.h1.exe     
unpackme_acprotect pro 2.1.0.exe  
lcgunpackme.exe       
beriav0.07_unpackmeiat.exe    
unpackme_chinaprotect 0.3.exe 
unpackme_berio 1.02.exe      
unpackme_antidote 1.4.exe      
unpackme_acprotect2.0.2006.03.10.g1.exe
unpackme_acprotect2.0.2006.03.10.f1.exe
unpackme_acprotect2.0.2006.03.10.e1.exe
unpackme_acprotect2.0.2006.03.10.d1.exe
unpackme_acprotect2.0.2006.03.10.c1.exe
unpackme_acprotect2.0.2006.03.10.b1.exe
unpackme_acprotect2.0.2006.03.10.a1.exe
unpackme_acprotect1.41.h1.exe    
unpackme_acprotect1.32.h1.exe    
unpackme_acprotect pro 2.1.0.exe 
lcgunpackme.exe       
copie de original.exe   
beriav0.07_unpackmeiat.exe     
beriav0.07_unpackmeiat.exe     
beriav0.07_unpackmeiat.exe
```
 
### Samples that Pin threw an exception on 
```
#!text
unpackme41_Yodas Protector.error.log
UnPackMe_COOLcryptor 0.9.error.log
UnPackMe_Enigma1.12.a1.error.log
UnPackMe_Enigma1.12.b1.error.log
UnPackMe_Enigma1.12.c1.error.log
UnPackMe_Enigma1.12.d1.error.log
UnPackMe_Enigma1.12.e1.error.log
UnPackMe_Enigma1.12.f1.error.log
UnPackMe_Enigma1.12.g1.error.log
UnPackMe_ExeCryptor2.1.20.c.error.log
UnPackMe_ExeCryptor2.1.20.h.error.log
UnPackMe_MPress 2.01 x64.error.log
UnPackMe_MPress 2.05 x64.error.log
UnPackMe_PELock1.06.a.error.log
UnPackMe_PELock1.06.b.error.log
UnPackMe_PELock1.06.c.error.log
UnPackMe_PELock1.06.d.error.log
UnPackMe_PELock1.06.e.error.log
UnPackMe_Sh4DoVV.error.log
WinLicense 2.0.8.0 UnpackME_prot.error.log
```
###  Pin Error Examples 
```
#!text

Pin 2.12 kit 55942
A: Source\pin\vm_ia32\emu_ia32.cpp:LEVEL_VM::EMULATOR_IA32::EmulateOneInstruction:LEVEL_VM::EMULATOR_IA32::EmulateOneInstruction:429: Unexpected instruction in emulator:   252 0x0 0x004f1638 jnz 0x5ae 

Pin 2.12 kit 55942
A: Source\pin\vm_ia32\jit_iarg_ia32.cpp:LEVEL_VM::SetupArgumentBranchTarget:LEVEL_VM::SetupArgumentBranchTarget:2463: assertion failed: INS_CallOrBranchIsMemoryIndirect(ins)

```

### Most Computationally Expensive 
```
#!text
Packer	                    Version	Lines
Themida                     1.9.1.0     19,955,014 (incomplete)
VMProtect                   1.8.a       13,114,113
HAC Crew Crypter            N/A         8,433,761 (incomplete)
ExeCryptor                  2.1.20.b    8,425,600
CISC-1                                  7,209,804 (incomplete)
free2_npse                              3,809,033 
Themida                     1.5.0.0.f   3,642,134 (incomplete)
VMProtect                   1.8.c       1,935,197
NoobyProtect SE Public      1.0.9.6     1,263,587
Hexalock Copy Protection    2.3         1,213,408 (incomplete)
ZProtect Enterprise         1.3.1       1,016,061
Zprotect                    1.4.4.0 	988,165
```

The incomplete means the log did not contain "[END]". False positives could be present due non-packed code being logged. If you would like to do the at home version please see the repo for tuts4me.cpp. 

### Loaded Modules (IMG) ###
Being alerted on when modules load in Pin is super simple. In main add the following function IMG_AddInstrumentFunction(whiteListImage, 0);. The first argument will be a function that is called everytime a module is loaded. 

```
#!c++

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
.....
```
I then use the following function to check if an address is within a module. 
```
#!c++

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
```
I would not recommend using a static address to check for loaded modules, such as if ( memory < 0x7c800000 ): not module. Some malware samples such as Andromeda allocates memory and executes code at higher memory addresses. For a good read on an older version of Andromeda check out 0xEBFE's [post](http://www.0xebfe.net/blog/2013/03/30/fooled-by-andromeda/).

### Consistently passing to a debugger or where I failed
 My original intention of this project was to learn C++, Pin and build a tool to bypass the unpacking routine. My first idea was this. 

1. Run packed code in Pin tool
1. Analyze log file to find the entry point of the packed code
1. Run packed code in Pin tool with an argument to break after a certain amount of logged branches and/or calls
1. Pass execution to debugger
1. Continue debugging in Ollydbg or Windbg

One through three is easily doable. Pin provides a tremendous amount of useful for source code examples. It was easy to hack together examples. The third part can be taken care of by using a global variable that counts all the logged branches or calls. 

```
#!c++

	if ( ( source & 0xffffffffffff0000 ) != ( dest & 0xffffffffffff0000 ) || LogBranches == TRUE )	
	{
		ins_count++;
		outFile << "[INS] Count " << dec << ins_count <<  " Src: " << "0x" << hex << source << " ;" << " Dism: " << getDism(source) << ';' << " Dest: " << "0x" << hex << dest << endl;
		if (ins_count == CountBreak )
		{
			thisIsTheEnd = TRUE;
			ATTEMPT_EXIT(ctxt);
		}
	}
	if (thisIsTheEnd)
	{
		outFile << "[EXIT] PIN_Detach() has been called" << endl;
		PIN_Detach(); 
	}
```

The ATTEMPT_EXIT is where things got interesting. I tried two approaches. The first approach was to change EIP via PIN_SetContextReg(ctxt,  REG_EIP, ADDRINT(1001)); to an address that I knew would cause an exception. After that was changed I would call PIN_ExecuteAt(ctxt) and then detach. Pin would be detached, the exception would be handled by the operating system, olldbg would be the just in time debugger and it would catch the exception. The debugger would be invoked but all the windows (register, CPU, stack, etc) would be blank. After switching to Windbg as the just in time debugger everything seemed to be working well until I realized some packers actually use exception handling.  

```
#!text

[INS] Count 1546 Src: 0x405317 ; Dism: jmp 0x40531a; Dest: 0x40531a
[INS] Count 1547 Src: 0x40531a ; Dism: jmp 0x40531d; Dest: 0x40531d
[INS] Count 1548 Src: 0x405320 ; Dism: jmp 0x405323; Dest: 0x405323
[INS] Count 1549 Src: 0x405323 ; Dism: jmp 0x405326; Dest: 0x405326
[INS] Count 1550 Src: 0x405326 ; Dism: jmp 0x405329; Dest: 0x405329   ; at count 1550 invoke exception 
[SEH] FS Found 0x7ffdf000    ; FS:[0] or  PIN_GetContextReg(ctxt, REG_SEG_FS_BASE )
[SEH] 0x12ec70 Handler 0x1712000   ; SEH handler in PIN
[SEH] 0x12f030 Handler 0x7c9032bc  ; SEH is a linked list, last exception handler will have a next address of  0xffffffff 
[SEH] 0x12f054 Handler 0x405291    ; first exception handler
[SEH] 0x12f414 Handler 0x7c9032bc
[SEH] 0x12f434 Handler 0x405249
[SEH] 0x12f7f4 Handler 0x7c9032bc
[SEH] 0x12f814 Handler 0x40523c
[SEH] 0x12fbd4 Handler 0x7c9032bc
[SEH] 0x12fbf4 Handler 0x40522f
[SEH] 0x12ffb4 Handler 0x7c9032bc
[SEH] 0x12ffe0 Handler 0x405222
[SEH] 0xffffffff Handler 0x7c839ac0
[SEH] End of SEH Chain at 0x7c839ac0
EIP: r @eip=0x405326 then F8   ; FYI for the user to change EIP in windbg 
[INS] Count 1551 Src: 0x405291 ; Dism: call 0x405267; Dest: 0x405267  ; address of the exception handler
[INS] Count 1552 Src: 0x405268 ; Dism: call 0x40526d; Dest: 0x40526d
[INS] Count 1553 Src: 0x40527d ; Dism: call 0x405283; Dest: 0x405283
[INS] Count 1554 Src: 0x405283 ; Dism: ret ; Dest: 0x405282
[INS] Count 1555 Src: 0x405282 ; Dism: ret ; Dest: 0x4052bc
[INS] Count 1556 Src: 0x4052bc ; Dism: call 0x4052c4; Dest: 0x4052c4
[INS] Count 1557 Src: 0x4052df ; Dism: call 0x4052e7; Dest: 0x4052e7
[INS] Count 1558 Src: 0x4052e7 ; Dism: call 0x405303; Dest: 0x405303
[INS] Count 1559 Src: 0x405304 ; Dism: jmp 0x405307; Dest: 0x405307
[INS] Count 1560 Src: 0x405307 ; Dism: jmp 0x40530a; Dest: 0x40530a

```

Here is some code that I used to loop through SEH. The code is not included in any of the example code in the repository. 


```
#!c++

void getSEH(CONTEXT * ctxt )
{
	int count = 0;
	int maxExcept = 500;
	UINT32 exceptAddr = 0;
	UINT32 temp = 0;
	UINT32 handler = 0;
	UINT32 stHandler = 0;
	UINT32 last = 0;
	UINT32 previous = 0;

	ADDRINT fs = PIN_GetContextReg(ctxt, REG_SEG_FS_BASE );
	outFile << "[SEH] FS Found 0x" << hex << fs << endl; 
	temp = UINT32(fs);

	// read the SEH 
	_asm mov eax, temp;
	_asm mov ebx, DWORD PTR [eax]; 
	_asm mov exceptAddr, ebx;
	// increment and get the handler address
	_asm add eax, 4;
	_asm mov ebx, DWORD PTR [eax];
	_asm mov temp, ebx;

	// limit the amount of SEH 
	for (; maxExcept >= 0; maxExcept--)
	{
		count++;
		outFile << "[SEH] 0x" << hex << exceptAddr << " Handler 0x" << hex << temp << endl;
		// BS. Pin does not allow it's DLL to show up as valid...
		// 1st - check if count is 1 (Pin SEH ) and img is invalid, if so skip
		// 2nd - check for SEH not in an img (ntdll.dll, etc)
		IMG img = IMG_FindByAddress(handler);
		if ((count == 1 && IMG_Valid(img) == FALSE))
			outFile << "[SEH] Pin SEH 0x" << hex << exceptAddr << " Handler 0x" << hex << temp << endl;
		else if (isAddressInModule(ADDRINT(temp)) == FALSE && handler == 0 )
			{
				// save off address of the processes first exception 
				previous = last;
				stHandler = exceptAddr;
				handler = temp;
			}
		// Get next item in SEH Chain 
		if (exceptAddr == 0xffffffff) 
		{ 
			outFile << "[SEH] End of SEH Chain at 0x" << hex << temp << endl;
			sehCount = count;
			return;
		}
		else
		{
			last = exceptAddr;
			_asm mov eax, exceptAddr;
			_asm mov ebx, DWORD PTR [eax];
			_asm add eax, 4;
			_asm mov eax, DWORD PTR [eax];
			_asm mov temp, eax;
			_asm mov exceptAddr, ebx;
		}
	}
	outFile << "[SEH] Not Found" << hex << exceptAddr << endl; 
	return;
}
```

I tried to change the exception handlers manually by changing the address in assembly. I wanted the first called exception handler to equal the handler first created by the operating system. My attempts at this approach failed. I don't think it is actually possible to change the values. Not 100% sure but I think it's due to Pin having a copy of the processes stack and registers. All of this gets changed once PIN_ExecuteAt gets called. Odds are I can still use the exception technique to bypass some packers. Not a big fan of knowing a technique can be broken with an exception handler. The second approach was calling EB FE (infinite loop) in an allocated block of memory. 

```
#!c++

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
```

EB FE is a classic approach for debugging. When the instructions are called the process will go in an infinite loop and then a debugger can be attached. In the code above I created an unsigned char that contains a unconditional jump and then a call to EB FE. The unconditional loops was included because I was unaware if an analysis routine would be invoked. This approach works until a debugger is attached. The issue can be best described by the email I sent to the Pin mailing list 

```
#!text

I'm looking for details on how I can detach Pin and then reattach to that process with a debugger? I'm currently trying an EB FE hack but once I attach with a debugger the process 
terminates. For example I have written a function that sets the context of EIP to and address of a buffer that contains opcodes for an unconditional jump and a call to JMP -2 (eb fe).

    unsigned char sc[] = {
     0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31, 0xC0, 0x83, 0xF8, 0x00, 0x74, 0x02, 0x90, 0x90, 0x90, 0x90, 0x61,0xeb, 0xfe, 0x90, 0x90
    };

    VOID * mem = WINDOWS::VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, sc, sizeof(sc));
    outFile << "[EXIT] EB FE is Address " << hex << mem << endl;
    PIN_SetContextReg(ctxt,  REG_EIP, ADDRINT(mem));
    thisIsTheEnd = TRUE;
    PIN_ExecuteAt(ctxt);

Once the context has been changed I call PIN_Detach() and then monitor when PIN_AddDetachFunction() is called. Once PIN_AddDetachFunction() gets called I attach a debugger to the 
process and EIP will be at the address of the infinite loop.

eax=022134fa ebx=022434c8 ecx=0012ff88 edx=02240154 esi=02213442 edi=0012ff7c
eip=02540012 esp=0012ff30 ebp=0012ff28 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
02540012 ebfe            jmp     02540012

Once I attach a debugger the process will be terminated with an exit code of -1. I have tested attaching with Windbg and Ollydbg and with different executables but I get the same results.
 I'm thinking this is caused by PIN. It looks like Pin is still executing or dealing with debug events (???) because PIN_AddDetachFunction() is executed a second time once I attach to 
the process. Here are the details from my log.

Before Debugger Attached
[EXIT] EB FE is Address 02540000
[EXIT] PIN_Detach() has been called
[EXIT] Pin tool: detach is completed

After Debugger Attached
[EXIT] EB FE is Address 02540000
[EXIT] PIN_Detach() has been called
[EXIT] Pin tool: detach is completed

[EXIT] Pin tool: detach is completed

Why does AddDetachFunction() get called once I attach with a debugger? Does anyone have ideas for a work around to continue execution in a debugger?
```

This code can be found in ebfe.cpp


Useful Links 

* https://software.intel.com/sites/landingpage/pintool/docs/65163/Pin/html/
* https://code.google.com/p/kerckhoffs/source/browse/#svn%2Ftrunk%2Ftrace_tool
* http://joxeankoret.com/blog/2012/11/04/a-simple-pin-tool-unpacker-for-the-linux-version-of-skype/
* http://shell-storm.org/repo/Notepad/
* https://github.com/jbremer/godware
* http://eindbazen.net/2013/04/pctf-2013-hypercomputer-1-bin-100/