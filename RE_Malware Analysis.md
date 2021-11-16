# What is malware?

# Give a brief Overview of PE Header?

1. Dos Header (_IMAGE_DOS_HEADER)
2. NT Header (_IMAGE_NT_HEADERS)
3. File Header (_IMAGE_FILE_HEADER) (Inside NT header)
4. Optional Header (_IMAGE_OPTIONAL_HEADER) (Inside NT header)
5. Section Headers (_IMAGE_SECTION_HEADER) (one for each section)


# What is threat intelligence?

# Explain the importance of software updates with regard to malware?

# What certifications do we have that will help we in this role?

# What is process injection?

Process injection is the method that malware can use to conceal its operations within the system. The malware has to go through a certain set of functions to carry out this technique.


# What hex values “Magic” field in the Optional header is set to?

The magic field in Option header shows if the PE file supports a 32-bit machine or 64-bit machine. Its value set to 010B for PE32 and 020B for PE64.


# How to determine the total size of the header in the disk?

SizeOfHeader in the optional header field shows the total size of the header in the disk.


# How many sections are possible in a PE file?

Inside File header, the NumberOfSections field shows the number of sections possible. Since it is a Word value(2 bytes) maximum sections possible is 0 to 65,535.


# What is the difference between RVA(Relative virtual address) and AVA(Absolute virtual address)?

AVA(also called as VA) is the original address in the virtual memory. whereas RVA is the relative address with respect to the Image Base. In calculation:
RVA = AVA – ImageBase
Means for AVA = 400100 and ImageBase = 400000, RVA will be 100.


# What is Import Address Table(IAT) & Export Address Table used for?  (Mostly asked)

IAT contains the address and a few other information of all DLL’s that needed to be imported by that image.  
The export table contains details about functions that the image exports to use by other programs.


# How important are software exploits with regard to malware analysts?

Software exploits have been increasingly used in recent years to sneak malware into a system because they need no user interaction and the malware’s malicious code can deliver its malicious code undetected.


# Name different tools we would use as a malware analyst, with the tools being used in different phases of malware analysis?

# What is assembly language ? What is reverse-engineering of malware and why is it important?


# What is TLS Callback?

TLS Callback is Address of Callbacks( functions that are generally stored on .tls section) that are executed when a process or thread is started or stopped. Since the windows loader first creates a thread for the process to run. The code in TLS Callback runs even before the program reaches the entry point.
Malware uses these functions/Callbacks to store there malicious code or Anti-Debug methods. It makes malware analysts confused while they are debugging the code since they first break at EntryPoint but the malicious code is already executed.


# What is the difference between SizeOfRawData and VirtualSize in the section header?

VirtualSize is the total size of a section when loaded into memory. Whereas SizeOfRawData is the size of the section when the image is in disk.


# Why is it good to have a hypervisor in a malware analysis lab?

In testing environments without a hypervisor, we need to have multiple computers running different operating systems. Hypervisors allow we to run multiple operating systems from one computer, which takes up fewer resources.


# What is the heuristic analysis?

Heuristic analysis is a malware and virus detection method that looks for common suspicious characteristics to find new and unknown malware and virus threats. This will keep an organization ahead of the curve with the hardest-to-find threats — the unknown ones.


# What is automated analysis?

Automated analysis is another way to analyze malware. Just as when other things are automated, when we automate the analysis of malware it is done to save time. This should be done in a sandbox to mitigate or eliminate any impact on your network.


# What is dynamic analysis?

Dynamic analysis, or behavior analysis, examines malware by executing it in a controlled, monitored environment in order to observe its behavior. This is preferable to static analysis, which conducts its examination without actually running the malware. The other major benefit of dynamic analysis is that we can execute the malware without harming your network devices.


# What is the difference between IDS and IPS?

IDS is an Intrusion Detection System and it only detects intrusions and the administrator has to take care of preventing the intrusion. Whereas, in IPS i.e., Intrusion Prevention System, the system detects the intrusion and also takes actions to prevent the intrusion.


# What are the response codes that can be received from a Web Application?

1xx – Informational responses
2xx – Success
3xx – Redirection
4xx – Client-side error
5xx – Server-side error


# Explain SSL Encryption

SSL(Secure Sockets Layer) is the industry-standard security technology creating encrypted connections between Web Server and a Browser. This is used to maintain data privacy and to protect the information in online transactions. The steps for establishing an SSL connection is as follows:

1.	A browser tries to connect to the webserver secured with SSL
2.	The browser sends a copy of its SSL certificate to the browser
3.	The browser checks if the SSL certificate is trustworthy or not. If it is trustworthy, then the browser sends a message to the webserver requesting to establish an encrypted connection
4.	The web server sends an acknowledgment to start an SSL encrypted connection
5.	SSL encrypted communication takes place between the browser and the webserver


# How an antivirus works? Explain in detail.

# How can an organization protect itself from a malware attack? Scenarios: After it happened, Before it's gonna happen & currently going on.

# Give your insight on recent malware attacks & there working.

# What's a XOR function?

# What is stub?

It is a piece of code used to stand in for some other programming functionality. A stub may simulate the behavior of existing code or be a temporary substitute for yet-to-be-developed code.


# Different types of packers.

# Explain various code obfuscation techniques?

# What Attracted we to malware analysis/working with malware in the first place?

# How would we handle a malware threat on a major production server?

Common answer: Restore entire image from backup.


# Describe a tool that we can implement at the firewall level of a network which would help we analyze malware threats.

Explain about any SIEM tool in contrast with firewall/malware threats.


# Role of documentation in Malware analysis.

# According to we, what's the biggest source of malware?

# How would we identify threats within software/programs?

Scan the software file with an antivirus program to see if it contains any hidden malware nasties. If we encounter a file that we are not sure of, compare it with current threat reports and malware blacklists to see it has been reported as a threat.


# Explain different kinds of malware?

# What is INT? Explain.

In OptionalHeader.DataDirectory, the second structure in the array points to _IMAGE_IMPORT_DESCRIPTOR.
_IMAGE_IMPORT_DESCRIPTOR is a structure that is present for each dll that needed to import. At 0x0c in import descriptor name field value set to name of dll (eg kernel32.dll).
Here OriginalFirstThunk points to Import Names table and FirstThunk points to IAT. INT points to array of names of functions (_IMAGE_IMPORT_BY_NAME) and IAT points to array of address of functions (_IMAGE_THUNK_DATA).

INT points to names of function whereas IAT points to address of function in the memory.


# Why we have two different Imports table(IAT and INT) but they both point to same structure in disk?

Initially when the image is not loaded in the memory the loader doesn't know the address of functions so it point IAT to the INT only.  But when image is loaded in memory it resolve the address of functions using INT entries and point IAT to the address.

IAT points to its own structure in Memory


# What information .pdb file contain? How the disassembler know the names of functions and variables when an image is loaded?

.pdb file contain debugging information of the program in windows. These debugging information have symbols of variables and functions.
In Debug Directory _IMAGE_DEBUG_DIRECTORY  address of Raw Data field points to debug information.
At particular offset of Debug data is the path of .pdb file associated with the image.


# What is difference between SizeOfRawData and VirtualSize in section header?

VirtualSize is the total size of a section when loaded into memory. Whereas SizeOfRawData is size of the section when the image is in disk.


# What is the use of .reloc section?

.reloc section contain relocation information for where to modify hard coded addresses which assume that the code was loaded at its preferred base address (defined with ImageBase) in memory.


# Can .rsrc section can have executable permission?

The permissions of a section is defined in Characteristics structure. So any section's permission can be changed to make it executable.
Interviewers ask specifically for .rsrc section because lots of malware( ex: stuxnet) embedded their code or whole binary inside the .rsrc section. Although  .rsrc is used to store icons or other graphical resources.


# What is difference between "mov" and "lea" instruction?

-> mov eax, [ebx]
-> lea eax, [ebx]
Suppose value in ebx is 0x400000. Then mov will go to address 0x400000 and copy 4 byte of data present their to eax register.Whereas lea will copy the address 0x400000 into eax. So, after the execution of each instruction value of eax in each case will be following(assuming at memory 0x400000 contain is 30).

eax = 30         (in case of mov)
eax = 0x400000   (in case of lea)
For definition mov copy the data from rm32 to destination (mov dest rm32) and lea(load effective address) will copy the address to destination (mov dest rm32).


# What are different calling conventions? What is difference between stdcall and cdecl calling convention?

Types of calling conventions:
1.	Stdcall (Standard Call)
2.	Cdecl (C declaration)
3.	FASTCALL
4.	THISCALL

In Stdcall arguments of a function is pushed in stack from right-to-left. And cleaning of stack is done by callee( who has been called) function.
In Cdecl arguments of a function is pushed in stack from left-to-right. And cleaning of stack is done by caller( who is calling) function.


# What calling convention we generally find in Windows C++ programs?

Windows program by default use StdCall but inside your IDE or compiler we have option to change the default convention.


# What is xor instruction do? Where it is used mostly in x86/64?

xor (exclusive or) gives output 0 if bits are same otherwise 0.

1.	1 xor 1 = 0
2.	0 xor 0 = 0
3.	1 xor 0 = 1
4.	0 xor 1 = 1
5.	
xor is mostly used in intel x86/64 to set a register value to 0. For example      

xor eax, eax will 0 the eax register.

Also xor eax, eax prefer over mov eax, 0 because of performance reason.


# What is the difference between "cmp" and "test" instructions?

In cmp the comparison is performed by subtracting the second operand from the first operand and then setting the status flags in the same manner as the sub instruction.
Test computes the bit-wise logical and of first operand (source 1 operand) and the second operand (source 2 operand) and sets the SF, ZF, and PF status flags according to the result.

cmp does the subtraction while test does the bitwise AND.


# What is x86 function prologue? Is it necessary to have those instructions in a programs function?

push ebp   //push the previous base pointer onto the stack.
mov ebp, esp  // set a new base pointer to create a new stack frame
No, It is not necessary to have function prologue. It is just used by compiler for  convention and security purposes.


# What are the most common registry location malware add them self for persistence?

Most common registry key which we need to remember is:

1.	HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
2.	HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run //Only for current user

Most of the time analyst use Autoruns tool from Sysinternals for looking at all such registry locations/keys.


# What API calls pattern malware show for DLL injection? (most asked)

1.	h=OpenProcess(,,proc_id)  	
2.	addr = VirtualAllocEx(h,,size,,,)	
3.	WriteProcessMem(h,addr,buf,size,...)	
4.	CreateRemoteThread(h,,,start,param,...)	


# What other process injection/hooking methods are available?

1.	Code injection
2.	Dll injection
3.	Dll search order hijacking
4.	APC injection
5.	IAT/EAT Hooking
6.	Inline hooking
7.	API Hooking and DLL Injection on Windows


# What is process hollowing?

Process hollowing is a technique used by malware in  which a legitimate process is loaded on the system solely to act as a  container for hostile code.

Reference: https://www.youtube.com/watch?v=9L9I1T5QDg4


# Do we use IDA or ollydbg? Which one of them is your favorite and Why? 

Depends on you.


# How many types of breakpoints are available in debugger? (most asked)

1.	Software breakpoint (use int 3 instruction)
2.	Hardware breakpoint (use debug registers DR0-3)
3.	Memory breakpoint (use guard pages)
4.	Conditional Breakpoint (Debugger specific)


# How many hardware breakpoint are available in debuggers?

There are 4 hardware breakpoints available in debugger. The reason why there are only 4 of them is because hardware breakpoint use debug register to store the memory address where breakpoint is set. There are only 8 debug register in Intel x86 -> DR0-DR7 from which only four are used for breakpoint.

1.	DR0-3 = breakpoint registers
2.	DR4-5 = reserved (unused)
3.	DR6 = Debug Status Register
4.	DR7 = Debug Control Register


# How software breakpoint work? Explain. (most asked)

INT 3 instruction is what debuggers are using when they are setting a “software breakpoint”.
Explaination:
When a debugger uses a software breakpoint, what it does is overwrite the first byte of the instruction at the specified address with CC byte (`int 3` opcode). It keeps its own list of which bytes it overwrote and where.
int Instruction is used to cause interrupt. Value 3 in int 3 tells the kernel go to vector 3 in interrupt table. While running the program when int 3 executed, exception(fault) occur which transfer the control to interrupt handler for interrupt vector 3. The interrupt handler transfer the control to registered debugger, which is usually the debugger we are using for setting the breakpoint. Then your debugger handle the breakpoint and remove the CC byte for further execution of instructions.


# In what condition we need to use hardware breakpoint instead of software? Why we use hardware breakpoints on dll's instead of software breakpoint?

Software breakpoint have limitation to be only set breakpoint on code section of the program since it put int 3 instruction. For other memory locations we cannot use software breakpoint.

Other then that if we try to put software breakpoint on any loaded dll's code, then every time we reload the program the breakpoint get removed because the int3 instruction get replace with the original instruction again.


# What are different anti-debugging/anti-analysis methods available are used by malwares?

There are lots of anti-analysis methods present. Ones that are used most are mentioned below.

PEB!IsDebugged flag is checked if contain 0 or 1. The instructions look like below:
mov eax, fs:[30]
mov eax, [eax+2]
test eax, eax
jnz exit_debugger_detected
kernel32!IsDebuggerPresent function is used.

GetTickCount or QueryPerformanceCounter calls are used for time based checking.

RDTSC instructions (Read Time Stamp Counter). They generally come in pairs, followed by a comparison.

rdtsc
mov ebx, eax
  ... some measured code ...
rdtsc
sub eax, ebx
cmp eax, ... some tick count ...
jg detected_debugger


# What packer does? (most asked)

There are lots of packers tool present that works little different from each other. But most commonly code and data is compressed/encrypted/encoded at a block level by packers. Then they add new section(eg .packed) where they put unpacking stub. They also modify header like changing Entry point to unpacking stub and few other fields.


# How to unpack packed code?

Interviewers may ask we if we have previous experience in unpacking packed executable. A general way to deal with this is as follow:
Often packer's stub start with pusha(push all general purpose register) and ends with popa(pop all registers) follow by a jump. The jump is at far location(mostly to other section of pe).
After the jump we land to OEP. We can dump the unpacked code to new pe file using ollydump plugin.


# How malware disable task manager or control panel?

Malware's can disable system utilities like task manager by modifying the security policy settings of the operating system. These policies are stored in registry at location HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System or HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System (for all users) .

We can change the value of a particular key using following windows shell command:

REG add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System  /v  DisableTaskMgr  /t REG_DWORD  /d /0 /f


# What Event viewer does and how to view events log?

Microsoft event viewer display your windows system logs about the recent activities in your system. It can give we good amount of information about the changes that a malicious program has recently done in a system. These changes include  failure in authentication, disabling antivirus etc. To view the events follow these steps:
1.	Click Start, point to Programs, point to Administrative Tools, and then click Event Viewer.
2.	In the console tree, right-click the appropriate log file, and then click Properties.
3.	Click the General tab.


# What are virtual function in C++?

If we have reversed any c++ program/malware then we must have come across something called as virtual functions. If a function is defined in both parent class as well as derived class with derived class function override the code of parent class function, then that function will be called virtual function. Learn more about this here. Example:

```
class base { 
public: 
    virtual void print() 
    { 
        cout << "print base class" << endl; 
    } 
  
    void show() 
    { 
        cout << "show base class" << endl; 
    } 
}; 
  
class derived : public base { 
public: 
    void print() 
    { 
        cout << "print derived class" << endl; 
    } 
  
    void show() 
    { 
        cout << "show derived class" << endl; 
    } 
}; 
In the above code print() is the virtual function which have different meaning for both classes.
```


# What are vtable in C++?

For every class that contains virtual functions, the compiler constructs a virtual table, a.k.a vtable. The vtable contains an entry for each virtual function accessible by the class and stores a pointer to its definition. Entries in the vtable can point to either functions declared in the class itself, or virtual functions inherited from a base class. Read more here.


# Different between reversing a C and C++ code.

Interviewer probably want to know what we usually find weird while reversing a c++ program. There can be many different assembly behaviors of c++ program like:
1.	Be aware that structs and objects will looks like array access while looking at assembly.
2.	If we find a same function, called twice with same parameter it may be the code of object creation. etc.


# How to identify local and global variable in a function by looking at its assembly? How local and global variable are different in assembly code?

1.	Global variable are allocated or declared in .data or .rdata sections of the program. So, they are called directly by their address. For ex: mov eax, 0x80903030.
2.	Local variable are allocated in stack and usually called using offset of ebp or esp. For ex: mov eax, [esp-10].


# What is DllMain in windows environment and how many times it runs when we load a dll from a program?

DllMain is highly used by malware to run their malicious code when a legitimate program load the malicious dll's.  
It is a function that by default run when a dll is loaded. Windows has provided this functionality for initialization and pre declaration related stuff. Its also a placeholder for the library-defined function.
When we start/end a program or a thread, then the dllMain is called. So, by default it will execute 4 times for a process.


# What are kernel objects or Kobjects?

There are various objects(structures) part of Windows kernel that  windows use for various purposes like process scheduling, I/O management. A kernel object is a virtual placeholder (data structure) for a resource that contains information about it. Everything on a computer will have an associated kernel object like every file, every process, every port, etc. Few important objects to remember and dig deep on are:
1.	EPROCESS
2.	KPCR
3.	KINTERRUPT
4.	IRP

Reference: http://www.nixhacker.com/understanding-windows-dkom-direct-kernel-object-manipulation-attacks-eprocess/


# How process communicate with each other in windows?

There can be many ways in which inter process communication (IPC) can happen in windows but we need to remember the ones that are mostly used by malware's or are widely used ones.
COM object - The Microsoft Component Object Model (COM) is a platform-independent, distributed, object-oriented system for creating binary software components that can interact.
In COM object access to an object's data is achieved exclusively through one or more sets of related functions. These function sets are called interfaces, and the functions of an interface are called methods.
Pipes - There are two types of pipes for two-way communication: anonymous pipes and named pipes. Anonymous pipes enable related processes to transfer information to each other. Typically, an anonymous pipe is used for redirecting the standard input or output of a child process so that it can exchange data with its parent process.
Named pipes are used to transfer data between processes that are not related processes and between processes on different computers. Typically, a named-pipe server process creates a named pipe with a well-known name or a name that is to be communicated to its clients. A simple usecase for this is remote kernel debugging. Read more here.
RPC - RPC is a function-level interface, with support for automatic data conversion and for communications with other operating systems. Using RPC, we can create high-performance, tightly coupled distributed applications.
Messaging Queues - The system passes input to a window procedure in the form of a message. Messages are generated by both the system and applications. The system generates a message at each input event—for example, when the user types, moves the mouse, or clicks a control such as a scroll bar.


# How mutex and critical section differ in windows?

Mutexes can be shared between processes, but always result in a system call to the kernel which has some overhead. Requires kernel interaction(kernel level permission) to work.
Critical sections can only be used within one process, but have the  advantage that they only switch to kernel mode in the case of contention  - Uncontended acquires, which should be the common case, are incredibly  fast.  In the case of contention, they enter the kernel to wait on some  synchronization primitive (like an event or semaphore). Doesn't requires kernel interaction(kernel level permission) to work.


# What we can look in PE header to identify if it's malware or not?

PE header gives few crucial details about the executable that can help we to identify if a sample is malicious or not. Before going into those details it is worth to remember a PE file can have totally normal header like other legitimate process but can be malicious. So, its not necessary that the header is definitely going to give we any required details. Now, lets look into the details.
Having non common sections (like .upx) can give a hint that the executable is packed hence can be malware.
.rsrc data directory can be a good place to look for anomalies. Usually, legitimate process have icons in .rsrc but malware may not have them but can have scripts, databases etc embedded inside them.
looking at entropy of each section, we can decide if the program is obstructed or not. High entropy(>7) usually implies obstructed section.
Malware can have obstructed imports or no imports at all, which can give a fair hint that the program is trying to hide its imports.
Looking at the imports we can guess what are the activities the program is trying to do. For example if we find a normal text editor have imports for functions like winsock2, regopen and CryptoAPI then it can be a fishy program(altough those imports can be used by a total legitimate process also.

Reference: http://cobweb.cs.uga.edu/~liao/PE_Final_Report.pdf


# How to know if a process in memory dump is a malware or rootkit using volatility? (Memory forensics)

In short: We can dump the process memory using memdump plugin and start analyzing them.
1.	Use pslist to list the processes with their pids.
2.	Use connscan to view the network connection done by a process.
3.	Use dlllist module to list the dll's and dump it using dlldump.
we can use malfind plugin to find the malicious process. This can be help to detect process injection.
There are more plugins that we can use like handles plugin to find much more information about the process. While analyzing if we find any anomalies in the data then we can conclude that the process may be malicious. Read more here.


# X64 calling convention.

The question is not at all advanced but mostly ignored in generic interviews. Although as a researcher it is must to have good understanding of x64 assembly and calling convention. Compare to x86 calling conventions(cdecl and stdcall), 64 bit system calling convention differs in these areas majorly:
1.	Arguments are passed using registers rather then pushing into stack. For windows the registers used for arguments from left to right is RCX, RDX, R8,R9 etc. For linux the pattern is RDI, RSI, RDX, RCX etc.
2.	Cleaning of stack is done by caller just like cdecl calling convention.
3.	Stack aligned in 16 bytes boundary.

# Explain Some Assembly Controls?

1. BRA Branch; Motorola 680×0, Motorola 68300; short (16 bit) unconditional branch relative to the current program counter.
2. JMP Jump; Motorola 680×0, Motorola 68300; unconditional jump (any valid effective addressing mode other than data register).
3. JMP Jump; Intel 80×86; unconditional jump (near [relative displacement from PC] or far; direct or indirect [based on contents of general purpose register, memory location, or indexed]).
4. JMP Jump; MIX; unconditional jump to location M; J-register loaded with the address of the instruction which would have been next if the jump had not been taken.
5. JSJ Jump, Save J-register; MIX; unconditional jump to location M; J-register unchanged.
6. Jcc Jump Conditionally; Intel 80×86; conditional jump (near [relative displacement from PC] or far; direct or indirect [based on contents of general purpose register, memory location, or indexed]) based on a tested condition: JA/JNBE, JAE/JNB, JB/JNAE, JBE/JNA, JC, JE/JZ, JNC, JNE/JNZ, JNP/JPO, JP/JPE, JG/JNLE, JGE/JNL, JL/JNGE, JLE/JNG, JNO, JNS, JO, JS.
7. Bcc Branch Conditionally; Motorola 680×0, Motorola 68300; short (16 bit) conditional branch relative to the current program counter based on a tested condition: BCC, BCS, BEQ, BGE, BGT, BHI, BLE, BLS, BLT, BMI, BNE, BPL, BVC, BVS.
8. JOV Jump on Overflow; MIX; conditional jump to location M if overflow toggle is on; if jump occurs, J-register loaded with the address of the instruction which would have been next if the jump had not been taken.

# What Is Assembly Condition Codes?

Condition codes are the list of possible conditions that can be tested during conditional instructions. Typical conditional instructions include: conditional branches, conditional jumps, and conditional subroutine calls. Some processors have a few additional data related conditional instructions, and some processors make every instruction conditional. Not all condition codes available for a processor will be implemented for every conditional instruction.

# What Is Data Movement?

Data movement instructions move data from one location to another. The source and destination locations are determined by the addressing modes, and can be registers or memory. Some processors have different instructions for loading registers and storing to memory, while other processors have a single instruction with flexible addressing modes.

# What Are Kinds Of Processors?

Processors can broadly be divided into the categories of: CISC, RISC, hybrid, and special purpose.

C++ Tutorial

# What Are Assembly Attributes?

Attributes are declarative tags in code that insert additional metadata into an assembly

C Interview Questions

# What Are The Types Of Assemblies?

1. Private Assemblies
2. Shared Assemblies

# Explain An Intermediate Language?

Assemblies are made up of IL code modules and the metadata that describes them. Although programs may be compiled via an IDE or the command line, in fact, they are simply translated into IL, not machine code. The actual machine code is not generated until the function that requires it is called.

# What Is The Maximum Number Of Classes That Can Be Contained In A Dll File?

There is no limit to the maximum number of classes that can be contained in a DLL file.

# Can One Dll File Contain The Compiled Code Of More Than One .net Language?

No, a DLL file can contain the compiled code of only one programming language.

# What Are The Different Types Of Assemblies? Explain Them In Detail


1. Private Assembly - Refers to the assembly that is used by a single application. Private assemblies are kept in a local folder in which the client application has been installed.

2. Public or Shared Assembly - Refers to the assembly that is allowed to be shared by multiple applications. A shared assembly must reside in Global Assembly Cache (GAC) with a strong name assigned to it.

For example, imagine that you have created a DLL containing information about your business logic. This DLL can be used by your client application. In order to run the client application, the DLL must be included in the same folder in which the client application has been installed. This makes the assembly private to your application. Now suppose that the DLL needs to be reused in different applications. Therefore, instead of copying the DLL in every client application folder, it can be placed in the global assembly cache using the GAC tool. These assemblies are called shared assemblies.

# Name The Different Components Of An Assembly?

1. Assembly manifest
2. MSIL source code
3. Type metadata
4. Resources

# What Is Difference Between Using A Macro And Inline Function?

The macro are just symbolic representations and cannot contain data type differentiations within the parameters that we give. The inline functions can have the data types too defined as a part of them. The disadvantage in using both is that the inclusion of condition checks may lead to increase in code space if the function is called many times.

# What Is A Semaphore? What Are The Different Types Of Semaphore?

The semaphore is an abstract data store that is used to control resource accesses across the various threads of execution or across different processes. There are two types of semaphores:

1. The binary semaphore which can take only 0,1 values. (used when there is contention for a single resource entity). 
2. The counting semaphore which can take incremental values to certain limit (used when number of resources is limited).

# Explain The Properties Of A Object Oriented Programming Language.

1. Encapsulation: The data that are related to the specific object are contained inside the object structure and hidden from the other entities of the environment.  
2. Polymorphism: The mechanism by which the same pointer can refer to different types of objects, which are basically linked by some generic commonality.
3. Abstraction: Hiding the data and implementation details from the real objects. The framework of reference is still present to be used by the other objects.
4. Inheritance: The way to take out the common features and have them as separate object entities only to be reused by the other objects in a modular fashion.

# What Are Little Endian And Big Endian Types Of Storage? How Can You Identify Which Type Of Allocation A System Follows?

The little endian memory representation allocates the least address to the least significant bit and the big endian is where the highest significant bit takes up the least addressed memory space. We can identify the system’s usage by defining an integer value and accessing it as a character.

```
int p=0x2; 
if(* (char *) &p == 0x2) printf (“little endiann”); 
else printf (“big endiann”);
```

# What Is A 'volatile' Variable?

Volatile is a keyword to specify the compiler that this variable value can change any time, so compiler should always read its value from its address, and not to use temporary registers to store its value and use in later part of the code. This is especially important to handle the memory mapped registers which are mapped as some variables or structures in embedded systems, such as hardware status registers etc, whose value can be changed anytime, depending on the hardware state.

1. Hardware registers in peripherals (for example, status registers)
2. Non-automatic variables referenced within an interrupt service routine
3. Variables shared by multiple tasks in a multi-threaded application

# What Is The Difference Between .exe And .dll Files?

EXE:

1. It is an executable file, which can be run independently.
2. EXE is an out-process component, which means that it runs in a separate process.
3. It cannot be reused in an application.
4. It has a main function.

DLL:

1. It is Dynamic Link Library that is used as a part of EXE or other DLLs. It cannot be run independently.
2. It runs in the application process memory, so it is called as in-process component.
3. It can be reused in an application.
4. It does not have a main function.
