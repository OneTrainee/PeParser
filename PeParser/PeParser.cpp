#include "PeParser.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <memory.h>
#include <Windows.h>
using namespace std;

PeParser::PeParser(const char* filePath) {

	this->errorCode = 0;
	this->fileBuffer = NULL;



	/******************************************
	*
	*           先读取二进制文件
	*
	*******************************************/


	// 以二进制形式打开文件
	FILE * file = NULL;
	int result = fopen_s(&file, filePath, "rb");
	if (file == 0) {
		this->errorCode = 1;
		return;
	}

	// 计算文件长度
	fseek(file, 0, SEEK_END); // 将指针移动到最后
	int size = ftell(file); // 计算从开始到最后的偏移
	this->fileSize = size;
	rewind(file); // 将指针再重新倒回去

	// 分配内存
	this->fileBuffer = (char*)malloc(size);
	if (this->fileBuffer == NULL) {
		fclose(file);
		this->errorCode = 2;
		return ;
	}

	// 读取文件
	memset(this->fileBuffer, 0, size);
	fread(this->fileBuffer, size, 1, file);
	fclose(file);



	/******************************************
	*
	*           进行PE指纹验证，如果不是PE文件，直接返回并释放内存
	*
	*******************************************/

	// 先检测 MZ
	if (!(fileBuffer[0] == 'M' && fileBuffer[1] == 'Z')) {
		free(this->fileBuffer);
		this->errorCode = 3;
		return ;
	}

	// 再检测 PE
	LONG peAddress = ((PIMAGE_DOS_HEADER)fileBuffer)->e_lfanew;
	if (!(fileBuffer[peAddress] == 'P' && fileBuffer[peAddress + 1] == 'E')) {
		free(this->fileBuffer);
		this->errorCode = 3;
		return;
	}

	/******************************************
	*
	*           对PE的各个数据段进行赋值
	*
	*******************************************/
	
	// DOS头、PE头、NT可选头
	this->pDosHeader = (PIMAGE_DOS_HEADER)this->fileBuffer; // DOS头
	//printf("%x  %x  %x", this->pDosHeader->e_lfanew, this->fileBuffer, this->pDosHeader);
	this->pNtHeaders = (PIMAGE_NT_HEADERS)(this->pDosHeader->e_lfanew + this->fileBuffer);
	this->pNtHeaders = (PIMAGE_NT_HEADERS)(this->pDosHeader->e_lfanew +(char*) this->pDosHeader); // 这种计算方式错误，但不知道原因
	this->pFileHeader = &(this->pNtHeaders->FileHeader);
	this->pOptionalHeader = &(this->pNtHeaders->OptionalHeader);
	
	// 循环赋值节区头
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {
		this->pSectionHeaders[i] = (PIMAGE_SECTION_HEADER )((char*)this->pOptionalHeader + this->pFileHeader->SizeOfOptionalHeader +  sizeof(IMAGE_SECTION_HEADER) * i);
	}

	/******************************************
	*
	*           预先判断对齐是否相等，简化 Rva 与 Foa 的计算过程
	*
	*******************************************/

	if (pOptionalHeader->FileAlignment == pOptionalHeader->SectionAlignment)
		this->alignSign = TRUE;
	else
		this->alignSign = FALSE;

	/******************************************
	*
	*           初始化导出表、导入表、重定位表
	*
	*******************************************/

	this->initExportTable();
	this->initImportTable();
	this->initRelocationTable();
}

DWORD PeParser::RvaToFoa(DWORD rvaValue) {
	//
	// 内存偏移 -> 文件偏移
	//

	if (alignSign) {
		return rvaValue;
	}

	errorCode = 0;

	// 直接返回
	if (rvaValue >= 0 && rvaValue <= sizeof(PIMAGE_DOS_HEADER) + sizeof(PIMAGE_NT_HEADERS)) {
		return rvaValue; 
	}

	// 判断落在哪个节区中
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {
		int sectionVritaulAddr =  this->pSectionHeaders[i]->VirtualAddress; // 虚拟地址
		int sectionVritualLength =  // 长度为两者中取最长的
			this->pSectionHeaders[i]->Misc.VirtualSize > this->pSectionHeaders[i]->Misc.PhysicalAddress ?
			this->pSectionHeaders[i]->Misc.VirtualSize : this->pSectionHeaders[i]->Misc.PhysicalAddress; 

		if (rvaValue >= sectionVritaulAddr && rvaValue <= sectionVritaulAddr + sectionVritualLength) {  // 如果在对应的节区中
			return rvaValue - sectionVritaulAddr + this->pSectionHeaders[i]->PointerToRawData;  
		 }

	}
	errorCode = 4;
	return 0;
}

DWORD PeParser::FoaToRva(DWORD foaValue) {
	//
	// 文件偏移 -> 内存偏移
	//
	if (this->alignSign)
		return foaValue;

	errorCode = 0;

	// 直接返回
	if (foaValue >= 0 && foaValue <= sizeof(PIMAGE_DOS_HEADER) + sizeof(PIMAGE_NT_HEADERS)) {
		return foaValue;
	}

	// 判断落在哪个节区中
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {
		int sectionRawAddr = this->pSectionHeaders[i]->PointerToRawData; // 节区偏移
		int sectionRawLength = this->pSectionHeaders[i]->SizeOfRawData; // 文件中的长度
		if (foaValue >= sectionRawAddr && foaValue <= sectionRawAddr + sectionRawLength) {  // 如果在对应的节区中
			return foaValue - sectionRawAddr + this->pSectionHeaders[i]->VirtualAddress;
		}

	}

	errorCode = 5;
	return 0;

}

DWORD PeParser::VaToRva(DWORD VaValue) {
	return VaValue - this->pOptionalHeader->ImageBase;
}

DWORD PeParser::RvaToVa(DWORD RvaValue) {
	return RvaValue + this->pOptionalHeader->ImageBase;
}

DWORD PeParser::SearchEmptyCodeSegmentAddress(int sizeOfCodeSegment) {
/*
@函数作用：注入代码时，搜索其可以注入的地点，并将该节属性设置为可执行
@传入参数：需要搜寻的代码片段的大小
@返回值：内存指针地址（并不是偏移）
@备注：通过开辟一块为零的内存，然后再节中不断比较比较该内存，为了提高效率，应该从节最后往前找。
	   如果找到，直接将内存中.
@警告：这是返回偏移量，如果想往该地址写入，应该加上其内存指针。
*/
	

	// 初始化一个比较内存，用完删除
	char* m = NULL;
	m = (char*)malloc(sizeOfCodeSegment);
	if (m == NULL) { 
		errorCode = 2;
		return 0;
	}
	memset(m, 0, sizeOfCodeSegment);

	BOOL searchFlag = FALSE;

	// 遍历节
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {

		PIMAGE_SECTION_HEADER p = this->pSectionHeaders[i];
		int temp =  p->PointerToRawData + p->SizeOfRawData; // 指向该节的最末尾，偏移。

		// 开始遍历该节是否找到空白区
		for (; temp != p->PointerToRawData; temp--) {
			char* tempStart = (char*)this->fileBuffer + temp - sizeOfCodeSegment;

			if (memcmp(tempStart, m, sizeOfCodeSegment) == 0) {
				// 找到空白区
				free(m); // 释放原先的内存
				p->Characteristics |= 0x60000020; // 修改该节属性为可执行
				return tempStart - (char*)this->fileBuffer; // 返回文件偏移
			}
		}

	}

	// 没找到，则释放内存，返回NULL
	free(m);
	return NULL;
}

BOOL PeParser::HookEntryPoint(const char *shellCode,int sizeOfShellCode) {
/*
@函数作用：将一段shellCode自动hook EntryPoint，后面自动追加jmp原EntryPoint
@参数：存储的在char[]的数组代码
      
*/
	DWORD shellCodeFileOffset = SearchEmptyCodeSegmentAddress(sizeOfShellCode + 5);
	DWORD originalEntry = this->pOptionalHeader->AddressOfEntryPoint;
	this->pOptionalHeader->AddressOfEntryPoint = this->FoaToRva((DWORD)shellCodeFileOffset); // FOA转RAW
	// 在代码后面添加 jmp originalOfEntry，之后全部写入文件中
	DWORD offsetEntry = originalEntry - (shellCodeFileOffset + sizeOfShellCode + 5); // res + offset = des; offset = des - res; 
	char* newMem = NULL;
	newMem = (char*)malloc(sizeOfShellCode + 5);
	if (newMem == NULL) {
		errorCode = 2;
		return FALSE;
	}
	memset(newMem, 0, sizeOfShellCode + 5);
	memcpy(newMem, shellCode, sizeOfShellCode); // shellCode
	newMem[sizeOfShellCode] = 0xE9; // jmp
	memcpy(newMem+sizeOfShellCode + 1, &offsetEntry, sizeof(DWORD)); // 相对跳转地址
	memcpy(this->fileBuffer + shellCodeFileOffset, newMem, sizeOfShellCode + 5); // 全部写入文件中去 
	free(newMem); // 释放新生成的内存


	return TRUE;


}

BOOL PeParser::SaveFile(const char* filePath) {
/*
@函数作用：传入路径，将新的PE文件写入
@参数：新生成的文件路径
*/
	FILE* file = NULL;
	int result = fopen_s(&file, filePath, "wb");
	if (file == NULL) {
		errorCode = 2;
		return FALSE;
	}
	fwrite(this->fileBuffer, this->fileSize , 1, file);
	fclose(file);
	return TRUE;
}

DWORD PeParser::AilgnByFile(DWORD originalValue){
/*
@函数作用: 计算按照文件对齐后的值
*/
	DWORD reminder = originalValue / this->pOptionalHeader->FileAlignment; 
	DWORD mod = originalValue % this->pOptionalHeader->FileAlignment;

	// 根据余数判断模的计算方式
	if (mod != 0)
		reminder += 1;

	return reminder * this->pOptionalHeader->FileAlignment;
}

DWORD PeParser::AilgnByMemory(DWORD originalValue) {
/*
@函数作用: 计算按照内存对齐后的值
*/
	DWORD reminder = originalValue / this->pOptionalHeader->SectionAlignment;
	DWORD mod = originalValue % this->pOptionalHeader->SectionAlignment;

	// 根据余数判断模的计算方式
	if (mod != 0)
		reminder += 1;

	return reminder * this->pOptionalHeader->SectionAlignment;
}
	
BOOL PeParser::ExtendLastSection(DWORD extendedByteLength) {
/*
@函数作用：
@函数参数：扩大的节的长度
@注意事项：扩大节相应的内存也要扩大，但是malloc后无法追加内存。
		   因此只能开辟更大的内存，此时要初始化PE成员变量。
		   记得原来的内存要被free掉
@注释：
	** 如何实现扩大节 **
	1. 先申请号对应的扩大内存
	2. 更新 sizeOfRawData & VirtualSize = 内存对齐[max(sizeOfRawData,VirtualSize)] + Length
	3. 修改sizeOfImage大小
	*********************
*/
		
	//
	// #1 开辟新内存，重新构建PE文件
	//
	if (!this->ExtendPeFile(extendedByteLength)) {
		errorCode = 6;
		return FALSE;
	}

	//
	// #2 更新 sizeOfRawData & VirtualSize = 内存对齐[max(sizeOfRawData,VirtualSize)] + Length
	//
	int finalSectionIndex = this->pFileHeader->NumberOfSections - 1;
	if (finalSectionIndex < 0) return FALSE; // 消除 C6385 警告
	PIMAGE_SECTION_HEADER p = this->pSectionHeaders[finalSectionIndex];
	DWORD newSize = max(p->Misc.VirtualSize, p->SizeOfRawData);
	newSize = this->AilgnByMemory(newSize) + extendedByteLength; 
	p->SizeOfRawData = newSize; // 更新文件最大值
	p->Misc.VirtualSize = newSize; // 更新内存最大值

	//
	// #3 更新 SizeOfImage, 内存对齐[SizeOfImage]+extendedByteLength
	//
	this->pOptionalHeader->SizeOfImage = this->AilgnByMemory(this->pOptionalHeader->SizeOfImage) + extendedByteLength;

	return TRUE;
}

BOOL PeParser::ExtendPeFile(DWORD extendedByteLength) {
/*
@函数作用：将PE文件扩大并重新构建各个PE成员，新增加的变量不会被赋值。
@函数参数：需要扩大的字节
@备注：malloc一个更大的文件空间，之后将原PE重新转移过去，内存指针之类的就需要重新初始化。
*/
	//开辟新内存
	char* newPe = (char*)malloc(extendedByteLength + this->fileSize); // 新的PE大小
	if (newPe == NULL) {
		errorCode = 2;
		return FALSE;
	}
	memcpy(newPe, this->fileBuffer, this->fileSize); // 文件复制到新的内存中
	memset(newPe + this->fileSize, 0, extendedByteLength); // 初始化之后的内存
	free(this->fileBuffer); // 释放原来的内存
	this->fileBuffer = newPe; // 赋值为新的内存
	this->fileSize += extendedByteLength; // 更新新的长度

	// DOS头、PE头、NT可选头
	this->pDosHeader = (PIMAGE_DOS_HEADER)this->fileBuffer; // DOS头
	this->pNtHeaders = (PIMAGE_NT_HEADERS)((char*)this->pDosHeader + this->pDosHeader->e_lfanew);
	this->pFileHeader = &(this->pNtHeaders->FileHeader);
	this->pOptionalHeader = &(this->pNtHeaders->OptionalHeader);

	// 循环赋值节区头
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {
		this->pSectionHeaders[i] = (PIMAGE_SECTION_HEADER)((char*)this->pOptionalHeader + this->pFileHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * i);
	}

	return TRUE;
}

BOOL PeParser::AddNewSection(DWORD newSectionLength, const char* newSectionName) {
/*
@函数作用：增加一个新的节区
@函数参数：新节区的长度 新节的名字
@备注：一定要修改前一个节的VirutalSize改为对齐后的大小，修改sizeOfImage;
	** 修改思路 **
	#1 构建新PE
	#2 更新最后一个节头的 virtualSize，按照内存对齐; SizeOfImage 按照内存对齐
	#3 更新NumberOfSection
	#4 复制节表，更新里面各种成员值
	***************
@警告：新节在内存的开始地址不能通过偏移计算，在《Windows逆向核心原理》中其后留下了一个坑说计算不一致，应该就是这个问题吧。
*/
	
	// #1 开辟新内存，重新构建PE文件
	if (!this->ExtendPeFile(newSectionLength)) {
		errorCode = 6;
		return FALSE;
	}
	
	// #2 更新最后一个节头的 virtualSize，按照内存对齐,修改sizeOfImage;
	int finalSectionIndex = this->pFileHeader->NumberOfSections - 1;
	if (finalSectionIndex < 0) return FALSE; // 消除 C6385 警告
	PIMAGE_SECTION_HEADER p = this->pSectionHeaders[finalSectionIndex];
	p->Misc.VirtualSize = this->AilgnByMemory(p->Misc.VirtualSize); 
	this->pOptionalHeader->SizeOfImage = this->AilgnByMemory(this->pOptionalHeader->SizeOfImage);

	// #3 更新NumberOfSection
	this->pFileHeader->NumberOfSections += 1;

	// #4 复制节表，更新里面各种成员值
	finalSectionIndex += 1;  // 最后一个节往后推
	this->pSectionHeaders[finalSectionIndex] = (PIMAGE_SECTION_HEADER)((char*)this->pOptionalHeader + 
		this->pFileHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * (finalSectionIndex)); // 节的数组中增加新值
	memcpy(this->pSectionHeaders[finalSectionIndex], p, sizeof(IMAGE_SECTION_HEADER)); // 最后一个节赋值到新节中
	p = this->pSectionHeaders[finalSectionIndex];
	memcpy(p->Name, newSectionName, 8); // 名字
	p->PointerToRawData = this->pSectionHeaders[finalSectionIndex-1]->PointerToRawData + this->pSectionHeaders[finalSectionIndex - 1]->SizeOfRawData; // 新一节地址 = 前一节地址+前一节大小
	p->VirtualAddress = this->pSectionHeaders[finalSectionIndex - 1]->VirtualAddress + this->pSectionHeaders[finalSectionIndex - 1]->Misc.VirtualSize; // 警告：这里内存如果直接从FoaToRaw会出错！！直接从前一节内存来计算
	p->SizeOfRawData = this->AilgnByFile(newSectionLength); // 文件大小
	p->Misc.VirtualSize = this->AilgnByMemory(newSectionLength); // 映射地址
	p->Characteristics |= 0x60000020; // 可执行属性
	this->pOptionalHeader->SizeOfImage += newSectionLength; // 新文件映射大小
	
	return TRUE;
}

BOOL PeParser::initExportTable() {
/*
@函数作用:初始化其导出表的各个函数，将其存放在 pExpoterMemberArr 中。
@注释:对于成员变量的名字，不用NULL，其在内存中自动
@警告: Ordinal 索引是WORD数组大小，不要忘记
	** 实现策略 **
	#1 先根据个数来初始化其导出表数组中
	#2 初始化函数索引号与对应的函数偏移
	#3 遍历函数名字，实现赋值
	**************

*/
	// 判断是否存在导出表
	if (this->pOptionalHeader->DataDirectory[0].VirtualAddress == 0) {
		this->lengthOfExpoterMemberArr = 0;
		return TRUE;
	}
	PIMAGE_EXPORT_DIRECTORY p = (PIMAGE_EXPORT_DIRECTORY)((char*)this->fileBuffer + this->pOptionalHeader->DataDirectory[0].VirtualAddress);
	int numberOfExpoterFunc = p->NumberOfFunctions; // 导出函数总个数
	int numberOfExpoterFuncWithName = p->NumberOfNames; // 有名字的个数
	this->lengthOfExpoterMemberArr = numberOfExpoterFunc; // 数组长度记录在this中 
	PDWORD32 funcAddr = (PDWORD32)((char*)this->fileBuffer + this->RvaToFoa(p->AddressOfFunctions)); // 函数内存地址数组，DWORD为单位
	PDWORD32 funcNameAddr = (PDWORD32)((char*)this->fileBuffer + this->RvaToFoa(p->AddressOfNames)); // 函数名称内存地址数组，DWORD为单位
	PWORD funcNameOrdinalAddr = (PWORD)((char*)this->fileBuffer + this->RvaToFoa(p->AddressOfNameOrdinals)); // 索引地址表,WORD为单位

	// #1 先根据个数来初始化其导出表数组中
	this->pExpoterMemberArr = NULL;
	this->pExpoterMemberArr = (PEXPOTER_MEMBER)malloc(sizeof(EXPOTER_MEMBER) * numberOfExpoterFunc);
	if (this->pExpoterMemberArr == NULL) {
		errorCode = 2;
		return FALSE;
	}

	// #2 初始化函数索引号与对应的函数偏移
	for (int i = 0; i < numberOfExpoterFunc; i++) {
		this->pExpoterMemberArr[i].index = i;
		this->pExpoterMemberArr[i].funcAddr = funcAddr[i];
	}

	// #3 遍历函数名字，实现赋值
	for (int i = 0; i < numberOfExpoterFuncWithName; i++) {
		WORD index = funcNameOrdinalAddr[i]; // 获取第i行对应的索引号
		this->pExpoterMemberArr[index].funcName = (char*)this->fileBuffer + this->RvaToFoa(funcNameAddr[i]); // 获取在内存中的名字 
	}

	return TRUE;

}

BOOL PeParser::initImportTable() {
/*
@函数作用：初始化PE导入表
@注释：
	** 实现导出表步骤 **
	#1 先判断导入表个数
	#2 为导入表申请内存，赋值数组
	#3  
	#4 对每个导出表进行处理
		#5 判断导出表个数
		#6 开辟内存，赋值数组
		#7 判断每个函数类型（序号||函数地址）
	*********************
@注意事项：HINT这里直接跳过，如果需要可以自行修改加上
*/
	
	// #1 先判断导入表个数
	if (this->pOptionalHeader->DataDirectory[1].VirtualAddress == 0) { // 判断是否存在导入表
		this->importerTotalTable.numberOfImporterTable = 0;
		return TRUE;
	}
	char* tempMemory = (char*)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR)); // 申请中间内存，之后释放出来
	if (tempMemory == NULL) {
		errorCode = 2;
		exit(0);
	}
	memset(tempMemory, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	char* p = this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[1].VirtualAddress); // 得到导出表在内存地址的偏移
	this->importerTotalTable.numberOfImporterTable = 0;
	while (memcmp(tempMemory, p, sizeof(IMAGE_IMPORT_DESCRIPTOR)) != 0 ){
		this->importerTotalTable.numberOfImporterTable++; // 导入表个数增加1
		p += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	
	// #2 为导入表申请内存，赋值数组
	this->importerTotalTable.importerTableArr = (PIMPORTER_TABLE)malloc(sizeof(IMPORTER_TABLE) * this->importerTotalTable.numberOfImporterTable); 

	// #3 释放原先内存，给导入表依次赋值名字
	free(tempMemory);
	PIMAGE_IMPORT_DESCRIPTOR t = (PIMAGE_IMPORT_DESCRIPTOR)((char*)this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[1].VirtualAddress));
	for (int i = 0; i < this->importerTotalTable.numberOfImporterTable; i++) {
		this->importerTotalTable.importerTableArr[i].tableName = (char*)this->fileBuffer + this->RvaToFoa(t->Name); // 名字赋值
		t++;
	}

	// #4 对每个导出表进行处理
	t = (PIMAGE_IMPORT_DESCRIPTOR)((char*)this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[1].VirtualAddress)); // 第一个导入表
	for (int i = 0; i < this->importerTotalTable.numberOfImporterTable; i++) {
		PDWORD32 pIntTable = (PDWORD32)((char*)this->fileBuffer + this->RvaToFoa(t->OriginalFirstThunk)); // 获取INT表
		this->importerTotalTable.importerTableArr[i].numberOfFunc = 0; // 初始化每个导入表的函数个数

		// #5 判断导出表个数
		this->importerTotalTable.importerTableArr[i].numberOfFunc = 0;
		while (*pIntTable != 0) {
			this->importerTotalTable.importerTableArr[i].numberOfFunc++;
			pIntTable++;
		}

		// #6 开辟内存，赋值数组
		this->importerTotalTable.importerTableArr[i].pImporterMemberArr = (PIMPORTER_MEMBER)malloc(sizeof(IMPORTER_MEMBER)* this->importerTotalTable.importerTableArr[i].numberOfFunc);

		// #7 判断每个函数类型（序号||函数地址）
		pIntTable = (PDWORD32)((char*)this->fileBuffer + this->RvaToFoa(t->OriginalFirstThunk));
		for (int j = 0; j < this->importerTotalTable.importerTableArr[i].numberOfFunc; j++) {
			if(*(pIntTable + j) & 0x80000000) { // 如果是导出序号序号
				this->importerTotalTable.importerTableArr[i].pImporterMemberArr[j].recordType = 1; // 表示类型为导出序号
				this->importerTotalTable.importerTableArr[i].pImporterMemberArr[j].importFuncIndex = *(pIntTable + j) & 0x7fffffff; // 做高位清零为获取的序号
			}
			else { // 如果是函数地址
				this->importerTotalTable.importerTableArr[i].pImporterMemberArr[j].recordType = 0; // 表示类型为函数导出名字
				// PIMAGE_IMPORT_BY_NAME + 2 直接跳过 HINT，获取名字，这很好理解 
				this->importerTotalTable.importerTableArr[i].pImporterMemberArr[j].importFuncName = (char*)this->fileBuffer + this->RvaToFoa(*(pIntTable + j)) + 2; 
			}
		}
		t++;// 下一个导入表
	}
	return TRUE;

}

BOOL PeParser::initRelocationTable() {
/*
@函数作用：初始化重定位表
@注释：
	** 重定位表作用 **
	#1 查找重定位表地址
	#2 扫描确定重定位块个数
	#3 申请对应内存块数据结构内存
	#4 对每个重定位块重新扫描，计算项目个数，内存指针取值
	*******************
*/
	// #1 查找重定位表地址
	if (this->pOptionalHeader->DataDirectory[5].VirtualAddress == 0) { // 判断是否存在重定位表
		this->relocationTable.numberOfRelocationBlocks = 0;
		return TRUE;
	}
	char* p = this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[5].VirtualAddress); // 获取重定位表地址

	// #2 扫描确定重定位块个数
	this->relocationTable.numberOfRelocationBlocks = 0;
	while (*(PDWORD32)p != 0) { // 判断是否为八个零
		this->relocationTable.numberOfRelocationBlocks++;
		p += *(PDWORD32)(p + 4); // 指向下一个重定位块
	}
	
	// #3 申请对应内存块数据结构内存
	this->relocationTable.pRelocationBlockArr = (PRELOCATION_BLOCK)malloc(sizeof(RELOCATION_BLOCK) * this->relocationTable.numberOfRelocationBlocks);
	if (this->relocationTable.pRelocationBlockArr != NULL) {
		errorCode = 2;
		return FALSE;
	}

	// #4 对每个重定位块重新扫描
	p = this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[5].VirtualAddress); // 获取重定位表地址
	for (int i = 0; i < this->relocationTable.numberOfRelocationBlocks; i++) {
		this->relocationTable.pRelocationBlockArr[i].numberOfItems = (*(PDWORD32)(p + 4) - 8) / 2; // 计算项数个数
		this->relocationTable.pRelocationBlockArr[i].pItemsArr = (PWORD)(p + 8); // 内存实现赋值
		p += *(PDWORD32)(p + 4); // 指向下一个重定位块
	}
	return TRUE;
}