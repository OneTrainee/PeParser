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
	*           �ȶ�ȡ�������ļ�
	*
	*******************************************/


	// �Զ�������ʽ���ļ�
	FILE * file = NULL;
	int result = fopen_s(&file, filePath, "rb");
	if (file == 0) {
		this->errorCode = 1;
		return;
	}

	// �����ļ�����
	fseek(file, 0, SEEK_END); // ��ָ���ƶ������
	int size = ftell(file); // ����ӿ�ʼ������ƫ��
	this->fileSize = size;
	rewind(file); // ��ָ�������µ���ȥ

	// �����ڴ�
	this->fileBuffer = (char*)malloc(size);
	if (this->fileBuffer == NULL) {
		fclose(file);
		this->errorCode = 2;
		return ;
	}

	// ��ȡ�ļ�
	memset(this->fileBuffer, 0, size);
	fread(this->fileBuffer, size, 1, file);
	fclose(file);



	/******************************************
	*
	*           ����PEָ����֤���������PE�ļ���ֱ�ӷ��ز��ͷ��ڴ�
	*
	*******************************************/

	// �ȼ�� MZ
	if (!(fileBuffer[0] == 'M' && fileBuffer[1] == 'Z')) {
		free(this->fileBuffer);
		this->errorCode = 3;
		return ;
	}

	// �ټ�� PE
	LONG peAddress = ((PIMAGE_DOS_HEADER)fileBuffer)->e_lfanew;
	if (!(fileBuffer[peAddress] == 'P' && fileBuffer[peAddress + 1] == 'E')) {
		free(this->fileBuffer);
		this->errorCode = 3;
		return;
	}

	/******************************************
	*
	*           ��PE�ĸ������ݶν��и�ֵ
	*
	*******************************************/
	
	// DOSͷ��PEͷ��NT��ѡͷ
	this->pDosHeader = (PIMAGE_DOS_HEADER)this->fileBuffer; // DOSͷ
	//printf("%x  %x  %x", this->pDosHeader->e_lfanew, this->fileBuffer, this->pDosHeader);
	this->pNtHeaders = (PIMAGE_NT_HEADERS)(this->pDosHeader->e_lfanew + this->fileBuffer);
	this->pNtHeaders = (PIMAGE_NT_HEADERS)(this->pDosHeader->e_lfanew +(char*) this->pDosHeader); // ���ּ��㷽ʽ���󣬵���֪��ԭ��
	this->pFileHeader = &(this->pNtHeaders->FileHeader);
	this->pOptionalHeader = &(this->pNtHeaders->OptionalHeader);
	
	// ѭ����ֵ����ͷ
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {
		this->pSectionHeaders[i] = (PIMAGE_SECTION_HEADER )((char*)this->pOptionalHeader + this->pFileHeader->SizeOfOptionalHeader +  sizeof(IMAGE_SECTION_HEADER) * i);
	}

	/******************************************
	*
	*           Ԥ���ж϶����Ƿ���ȣ��� Rva �� Foa �ļ������
	*
	*******************************************/

	if (pOptionalHeader->FileAlignment == pOptionalHeader->SectionAlignment)
		this->alignSign = TRUE;
	else
		this->alignSign = FALSE;

	/******************************************
	*
	*           ��ʼ��������������ض�λ��
	*
	*******************************************/

	this->initExportTable();
	this->initImportTable();
	this->initRelocationTable();
}

DWORD PeParser::RvaToFoa(DWORD rvaValue) {
	//
	// �ڴ�ƫ�� -> �ļ�ƫ��
	//

	if (alignSign) {
		return rvaValue;
	}

	errorCode = 0;

	// ֱ�ӷ���
	if (rvaValue >= 0 && rvaValue <= sizeof(PIMAGE_DOS_HEADER) + sizeof(PIMAGE_NT_HEADERS)) {
		return rvaValue; 
	}

	// �ж������ĸ�������
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {
		int sectionVritaulAddr =  this->pSectionHeaders[i]->VirtualAddress; // �����ַ
		int sectionVritualLength =  // ����Ϊ������ȡ���
			this->pSectionHeaders[i]->Misc.VirtualSize > this->pSectionHeaders[i]->Misc.PhysicalAddress ?
			this->pSectionHeaders[i]->Misc.VirtualSize : this->pSectionHeaders[i]->Misc.PhysicalAddress; 

		if (rvaValue >= sectionVritaulAddr && rvaValue <= sectionVritaulAddr + sectionVritualLength) {  // ����ڶ�Ӧ�Ľ�����
			return rvaValue - sectionVritaulAddr + this->pSectionHeaders[i]->PointerToRawData;  
		 }

	}
	errorCode = 4;
	return 0;
}

DWORD PeParser::FoaToRva(DWORD foaValue) {
	//
	// �ļ�ƫ�� -> �ڴ�ƫ��
	//
	if (this->alignSign)
		return foaValue;

	errorCode = 0;

	// ֱ�ӷ���
	if (foaValue >= 0 && foaValue <= sizeof(PIMAGE_DOS_HEADER) + sizeof(PIMAGE_NT_HEADERS)) {
		return foaValue;
	}

	// �ж������ĸ�������
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {
		int sectionRawAddr = this->pSectionHeaders[i]->PointerToRawData; // ����ƫ��
		int sectionRawLength = this->pSectionHeaders[i]->SizeOfRawData; // �ļ��еĳ���
		if (foaValue >= sectionRawAddr && foaValue <= sectionRawAddr + sectionRawLength) {  // ����ڶ�Ӧ�Ľ�����
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
@�������ã�ע�����ʱ�����������ע��ĵص㣬�����ý���������Ϊ��ִ��
@�����������Ҫ��Ѱ�Ĵ���Ƭ�εĴ�С
@����ֵ���ڴ�ָ���ַ��������ƫ�ƣ�
@��ע��ͨ������һ��Ϊ����ڴ棬Ȼ���ٽ��в��ϱȽϱȽϸ��ڴ棬Ϊ�����Ч�ʣ�Ӧ�ôӽ������ǰ�ҡ�
	   ����ҵ���ֱ�ӽ��ڴ���.
@���棺���Ƿ���ƫ��������������õ�ַд�룬Ӧ�ü������ڴ�ָ�롣
*/
	

	// ��ʼ��һ���Ƚ��ڴ棬����ɾ��
	char* m = NULL;
	m = (char*)malloc(sizeOfCodeSegment);
	if (m == NULL) { 
		errorCode = 2;
		return 0;
	}
	memset(m, 0, sizeOfCodeSegment);

	BOOL searchFlag = FALSE;

	// ������
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {

		PIMAGE_SECTION_HEADER p = this->pSectionHeaders[i];
		int temp =  p->PointerToRawData + p->SizeOfRawData; // ָ��ýڵ���ĩβ��ƫ�ơ�

		// ��ʼ�����ý��Ƿ��ҵ��հ���
		for (; temp != p->PointerToRawData; temp--) {
			char* tempStart = (char*)this->fileBuffer + temp - sizeOfCodeSegment;

			if (memcmp(tempStart, m, sizeOfCodeSegment) == 0) {
				// �ҵ��հ���
				free(m); // �ͷ�ԭ�ȵ��ڴ�
				p->Characteristics |= 0x60000020; // �޸ĸý�����Ϊ��ִ��
				return tempStart - (char*)this->fileBuffer; // �����ļ�ƫ��
			}
		}

	}

	// û�ҵ������ͷ��ڴ棬����NULL
	free(m);
	return NULL;
}

BOOL PeParser::HookEntryPoint(const char *shellCode,int sizeOfShellCode) {
/*
@�������ã���һ��shellCode�Զ�hook EntryPoint�������Զ�׷��jmpԭEntryPoint
@�������洢����char[]���������
      
*/
	DWORD shellCodeFileOffset = SearchEmptyCodeSegmentAddress(sizeOfShellCode + 5);
	DWORD originalEntry = this->pOptionalHeader->AddressOfEntryPoint;
	this->pOptionalHeader->AddressOfEntryPoint = this->FoaToRva((DWORD)shellCodeFileOffset); // FOAתRAW
	// �ڴ��������� jmp originalOfEntry��֮��ȫ��д���ļ���
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
	memcpy(newMem+sizeOfShellCode + 1, &offsetEntry, sizeof(DWORD)); // �����ת��ַ
	memcpy(this->fileBuffer + shellCodeFileOffset, newMem, sizeOfShellCode + 5); // ȫ��д���ļ���ȥ 
	free(newMem); // �ͷ������ɵ��ڴ�


	return TRUE;


}

BOOL PeParser::SaveFile(const char* filePath) {
/*
@�������ã�����·�������µ�PE�ļ�д��
@�����������ɵ��ļ�·��
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
@��������: ���㰴���ļ�������ֵ
*/
	DWORD reminder = originalValue / this->pOptionalHeader->FileAlignment; 
	DWORD mod = originalValue % this->pOptionalHeader->FileAlignment;

	// ���������ж�ģ�ļ��㷽ʽ
	if (mod != 0)
		reminder += 1;

	return reminder * this->pOptionalHeader->FileAlignment;
}

DWORD PeParser::AilgnByMemory(DWORD originalValue) {
/*
@��������: ���㰴���ڴ������ֵ
*/
	DWORD reminder = originalValue / this->pOptionalHeader->SectionAlignment;
	DWORD mod = originalValue % this->pOptionalHeader->SectionAlignment;

	// ���������ж�ģ�ļ��㷽ʽ
	if (mod != 0)
		reminder += 1;

	return reminder * this->pOptionalHeader->SectionAlignment;
}
	
BOOL PeParser::ExtendLastSection(DWORD extendedByteLength) {
/*
@�������ã�
@��������������Ľڵĳ���
@ע������������Ӧ���ڴ�ҲҪ���󣬵���malloc���޷�׷���ڴ档
		   ���ֻ�ܿ��ٸ�����ڴ棬��ʱҪ��ʼ��PE��Ա������
		   �ǵ�ԭ�����ڴ�Ҫ��free��
@ע�ͣ�
	** ���ʵ������� **
	1. ������Ŷ�Ӧ�������ڴ�
	2. ���� sizeOfRawData & VirtualSize = �ڴ����[max(sizeOfRawData,VirtualSize)] + Length
	3. �޸�sizeOfImage��С
	*********************
*/
		
	//
	// #1 �������ڴ棬���¹���PE�ļ�
	//
	if (!this->ExtendPeFile(extendedByteLength)) {
		errorCode = 6;
		return FALSE;
	}

	//
	// #2 ���� sizeOfRawData & VirtualSize = �ڴ����[max(sizeOfRawData,VirtualSize)] + Length
	//
	int finalSectionIndex = this->pFileHeader->NumberOfSections - 1;
	if (finalSectionIndex < 0) return FALSE; // ���� C6385 ����
	PIMAGE_SECTION_HEADER p = this->pSectionHeaders[finalSectionIndex];
	DWORD newSize = max(p->Misc.VirtualSize, p->SizeOfRawData);
	newSize = this->AilgnByMemory(newSize) + extendedByteLength; 
	p->SizeOfRawData = newSize; // �����ļ����ֵ
	p->Misc.VirtualSize = newSize; // �����ڴ����ֵ

	//
	// #3 ���� SizeOfImage, �ڴ����[SizeOfImage]+extendedByteLength
	//
	this->pOptionalHeader->SizeOfImage = this->AilgnByMemory(this->pOptionalHeader->SizeOfImage) + extendedByteLength;

	return TRUE;
}

BOOL PeParser::ExtendPeFile(DWORD extendedByteLength) {
/*
@�������ã���PE�ļ��������¹�������PE��Ա�������ӵı������ᱻ��ֵ��
@������������Ҫ������ֽ�
@��ע��mallocһ��������ļ��ռ䣬֮��ԭPE����ת�ƹ�ȥ���ڴ�ָ��֮��ľ���Ҫ���³�ʼ����
*/
	//�������ڴ�
	char* newPe = (char*)malloc(extendedByteLength + this->fileSize); // �µ�PE��С
	if (newPe == NULL) {
		errorCode = 2;
		return FALSE;
	}
	memcpy(newPe, this->fileBuffer, this->fileSize); // �ļ����Ƶ��µ��ڴ���
	memset(newPe + this->fileSize, 0, extendedByteLength); // ��ʼ��֮����ڴ�
	free(this->fileBuffer); // �ͷ�ԭ�����ڴ�
	this->fileBuffer = newPe; // ��ֵΪ�µ��ڴ�
	this->fileSize += extendedByteLength; // �����µĳ���

	// DOSͷ��PEͷ��NT��ѡͷ
	this->pDosHeader = (PIMAGE_DOS_HEADER)this->fileBuffer; // DOSͷ
	this->pNtHeaders = (PIMAGE_NT_HEADERS)((char*)this->pDosHeader + this->pDosHeader->e_lfanew);
	this->pFileHeader = &(this->pNtHeaders->FileHeader);
	this->pOptionalHeader = &(this->pNtHeaders->OptionalHeader);

	// ѭ����ֵ����ͷ
	for (int i = 0; i < this->pFileHeader->NumberOfSections; i++) {
		this->pSectionHeaders[i] = (PIMAGE_SECTION_HEADER)((char*)this->pOptionalHeader + this->pFileHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * i);
	}

	return TRUE;
}

BOOL PeParser::AddNewSection(DWORD newSectionLength, const char* newSectionName) {
/*
@�������ã�����һ���µĽ���
@�����������½����ĳ��� �½ڵ�����
@��ע��һ��Ҫ�޸�ǰһ���ڵ�VirutalSize��Ϊ�����Ĵ�С���޸�sizeOfImage;
	** �޸�˼· **
	#1 ������PE
	#2 �������һ����ͷ�� virtualSize�������ڴ����; SizeOfImage �����ڴ����
	#3 ����NumberOfSection
	#4 ���ƽڱ�����������ֳ�Աֵ
	***************
@���棺�½����ڴ�Ŀ�ʼ��ַ����ͨ��ƫ�Ƽ��㣬�ڡ�Windows�������ԭ�������������һ����˵���㲻һ�£�Ӧ�þ����������ɡ�
*/
	
	// #1 �������ڴ棬���¹���PE�ļ�
	if (!this->ExtendPeFile(newSectionLength)) {
		errorCode = 6;
		return FALSE;
	}
	
	// #2 �������һ����ͷ�� virtualSize�������ڴ����,�޸�sizeOfImage;
	int finalSectionIndex = this->pFileHeader->NumberOfSections - 1;
	if (finalSectionIndex < 0) return FALSE; // ���� C6385 ����
	PIMAGE_SECTION_HEADER p = this->pSectionHeaders[finalSectionIndex];
	p->Misc.VirtualSize = this->AilgnByMemory(p->Misc.VirtualSize); 
	this->pOptionalHeader->SizeOfImage = this->AilgnByMemory(this->pOptionalHeader->SizeOfImage);

	// #3 ����NumberOfSection
	this->pFileHeader->NumberOfSections += 1;

	// #4 ���ƽڱ�����������ֳ�Աֵ
	finalSectionIndex += 1;  // ���һ����������
	this->pSectionHeaders[finalSectionIndex] = (PIMAGE_SECTION_HEADER)((char*)this->pOptionalHeader + 
		this->pFileHeader->SizeOfOptionalHeader + sizeof(IMAGE_SECTION_HEADER) * (finalSectionIndex)); // �ڵ�������������ֵ
	memcpy(this->pSectionHeaders[finalSectionIndex], p, sizeof(IMAGE_SECTION_HEADER)); // ���һ���ڸ�ֵ���½���
	p = this->pSectionHeaders[finalSectionIndex];
	memcpy(p->Name, newSectionName, 8); // ����
	p->PointerToRawData = this->pSectionHeaders[finalSectionIndex-1]->PointerToRawData + this->pSectionHeaders[finalSectionIndex - 1]->SizeOfRawData; // ��һ�ڵ�ַ = ǰһ�ڵ�ַ+ǰһ�ڴ�С
	p->VirtualAddress = this->pSectionHeaders[finalSectionIndex - 1]->VirtualAddress + this->pSectionHeaders[finalSectionIndex - 1]->Misc.VirtualSize; // ���棺�����ڴ����ֱ�Ӵ�FoaToRaw�������ֱ�Ӵ�ǰһ���ڴ�������
	p->SizeOfRawData = this->AilgnByFile(newSectionLength); // �ļ���С
	p->Misc.VirtualSize = this->AilgnByMemory(newSectionLength); // ӳ���ַ
	p->Characteristics |= 0x60000020; // ��ִ������
	this->pOptionalHeader->SizeOfImage += newSectionLength; // ���ļ�ӳ���С
	
	return TRUE;
}

BOOL PeParser::initExportTable() {
/*
@��������:��ʼ���䵼����ĸ����������������� pExpoterMemberArr �С�
@ע��:���ڳ�Ա���������֣�����NULL�������ڴ����Զ�
@����: Ordinal ������WORD�����С����Ҫ����
	** ʵ�ֲ��� **
	#1 �ȸ��ݸ�������ʼ���䵼����������
	#2 ��ʼ���������������Ӧ�ĺ���ƫ��
	#3 �����������֣�ʵ�ָ�ֵ
	**************

*/
	// �ж��Ƿ���ڵ�����
	if (this->pOptionalHeader->DataDirectory[0].VirtualAddress == 0) {
		this->lengthOfExpoterMemberArr = 0;
		return TRUE;
	}
	PIMAGE_EXPORT_DIRECTORY p = (PIMAGE_EXPORT_DIRECTORY)((char*)this->fileBuffer + this->pOptionalHeader->DataDirectory[0].VirtualAddress);
	int numberOfExpoterFunc = p->NumberOfFunctions; // ���������ܸ���
	int numberOfExpoterFuncWithName = p->NumberOfNames; // �����ֵĸ���
	this->lengthOfExpoterMemberArr = numberOfExpoterFunc; // ���鳤�ȼ�¼��this�� 
	PDWORD32 funcAddr = (PDWORD32)((char*)this->fileBuffer + this->RvaToFoa(p->AddressOfFunctions)); // �����ڴ��ַ���飬DWORDΪ��λ
	PDWORD32 funcNameAddr = (PDWORD32)((char*)this->fileBuffer + this->RvaToFoa(p->AddressOfNames)); // ���������ڴ��ַ���飬DWORDΪ��λ
	PWORD funcNameOrdinalAddr = (PWORD)((char*)this->fileBuffer + this->RvaToFoa(p->AddressOfNameOrdinals)); // ������ַ��,WORDΪ��λ

	// #1 �ȸ��ݸ�������ʼ���䵼����������
	this->pExpoterMemberArr = NULL;
	this->pExpoterMemberArr = (PEXPOTER_MEMBER)malloc(sizeof(EXPOTER_MEMBER) * numberOfExpoterFunc);
	if (this->pExpoterMemberArr == NULL) {
		errorCode = 2;
		return FALSE;
	}

	// #2 ��ʼ���������������Ӧ�ĺ���ƫ��
	for (int i = 0; i < numberOfExpoterFunc; i++) {
		this->pExpoterMemberArr[i].index = i;
		this->pExpoterMemberArr[i].funcAddr = funcAddr[i];
	}

	// #3 �����������֣�ʵ�ָ�ֵ
	for (int i = 0; i < numberOfExpoterFuncWithName; i++) {
		WORD index = funcNameOrdinalAddr[i]; // ��ȡ��i�ж�Ӧ��������
		this->pExpoterMemberArr[index].funcName = (char*)this->fileBuffer + this->RvaToFoa(funcNameAddr[i]); // ��ȡ���ڴ��е����� 
	}

	return TRUE;

}

BOOL PeParser::initImportTable() {
/*
@�������ã���ʼ��PE�����
@ע�ͣ�
	** ʵ�ֵ������� **
	#1 ���жϵ�������
	#2 Ϊ����������ڴ棬��ֵ����
	#3  
	#4 ��ÿ����������д���
		#5 �жϵ��������
		#6 �����ڴ棬��ֵ����
		#7 �ж�ÿ���������ͣ����||������ַ��
	*********************
@ע�����HINT����ֱ�������������Ҫ���������޸ļ���
*/
	
	// #1 ���жϵ�������
	if (this->pOptionalHeader->DataDirectory[1].VirtualAddress == 0) { // �ж��Ƿ���ڵ����
		this->importerTotalTable.numberOfImporterTable = 0;
		return TRUE;
	}
	char* tempMemory = (char*)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR)); // �����м��ڴ棬֮���ͷų���
	if (tempMemory == NULL) {
		errorCode = 2;
		exit(0);
	}
	memset(tempMemory, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	char* p = this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[1].VirtualAddress); // �õ����������ڴ��ַ��ƫ��
	this->importerTotalTable.numberOfImporterTable = 0;
	while (memcmp(tempMemory, p, sizeof(IMAGE_IMPORT_DESCRIPTOR)) != 0 ){
		this->importerTotalTable.numberOfImporterTable++; // ������������1
		p += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	
	// #2 Ϊ����������ڴ棬��ֵ����
	this->importerTotalTable.importerTableArr = (PIMPORTER_TABLE)malloc(sizeof(IMPORTER_TABLE) * this->importerTotalTable.numberOfImporterTable); 

	// #3 �ͷ�ԭ���ڴ棬����������θ�ֵ����
	free(tempMemory);
	PIMAGE_IMPORT_DESCRIPTOR t = (PIMAGE_IMPORT_DESCRIPTOR)((char*)this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[1].VirtualAddress));
	for (int i = 0; i < this->importerTotalTable.numberOfImporterTable; i++) {
		this->importerTotalTable.importerTableArr[i].tableName = (char*)this->fileBuffer + this->RvaToFoa(t->Name); // ���ָ�ֵ
		t++;
	}

	// #4 ��ÿ����������д���
	t = (PIMAGE_IMPORT_DESCRIPTOR)((char*)this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[1].VirtualAddress)); // ��һ�������
	for (int i = 0; i < this->importerTotalTable.numberOfImporterTable; i++) {
		PDWORD32 pIntTable = (PDWORD32)((char*)this->fileBuffer + this->RvaToFoa(t->OriginalFirstThunk)); // ��ȡINT��
		this->importerTotalTable.importerTableArr[i].numberOfFunc = 0; // ��ʼ��ÿ�������ĺ�������

		// #5 �жϵ��������
		this->importerTotalTable.importerTableArr[i].numberOfFunc = 0;
		while (*pIntTable != 0) {
			this->importerTotalTable.importerTableArr[i].numberOfFunc++;
			pIntTable++;
		}

		// #6 �����ڴ棬��ֵ����
		this->importerTotalTable.importerTableArr[i].pImporterMemberArr = (PIMPORTER_MEMBER)malloc(sizeof(IMPORTER_MEMBER)* this->importerTotalTable.importerTableArr[i].numberOfFunc);

		// #7 �ж�ÿ���������ͣ����||������ַ��
		pIntTable = (PDWORD32)((char*)this->fileBuffer + this->RvaToFoa(t->OriginalFirstThunk));
		for (int j = 0; j < this->importerTotalTable.importerTableArr[i].numberOfFunc; j++) {
			if(*(pIntTable + j) & 0x80000000) { // ����ǵ���������
				this->importerTotalTable.importerTableArr[i].pImporterMemberArr[j].recordType = 1; // ��ʾ����Ϊ�������
				this->importerTotalTable.importerTableArr[i].pImporterMemberArr[j].importFuncIndex = *(pIntTable + j) & 0x7fffffff; // ����λ����Ϊ��ȡ�����
			}
			else { // ����Ǻ�����ַ
				this->importerTotalTable.importerTableArr[i].pImporterMemberArr[j].recordType = 0; // ��ʾ����Ϊ������������
				// PIMAGE_IMPORT_BY_NAME + 2 ֱ������ HINT����ȡ���֣���ܺ���� 
				this->importerTotalTable.importerTableArr[i].pImporterMemberArr[j].importFuncName = (char*)this->fileBuffer + this->RvaToFoa(*(pIntTable + j)) + 2; 
			}
		}
		t++;// ��һ�������
	}
	return TRUE;

}

BOOL PeParser::initRelocationTable() {
/*
@�������ã���ʼ���ض�λ��
@ע�ͣ�
	** �ض�λ������ **
	#1 �����ض�λ���ַ
	#2 ɨ��ȷ���ض�λ�����
	#3 �����Ӧ�ڴ�����ݽṹ�ڴ�
	#4 ��ÿ���ض�λ������ɨ�裬������Ŀ�������ڴ�ָ��ȡֵ
	*******************
*/
	// #1 �����ض�λ���ַ
	if (this->pOptionalHeader->DataDirectory[5].VirtualAddress == 0) { // �ж��Ƿ�����ض�λ��
		this->relocationTable.numberOfRelocationBlocks = 0;
		return TRUE;
	}
	char* p = this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[5].VirtualAddress); // ��ȡ�ض�λ���ַ

	// #2 ɨ��ȷ���ض�λ�����
	this->relocationTable.numberOfRelocationBlocks = 0;
	while (*(PDWORD32)p != 0) { // �ж��Ƿ�Ϊ�˸���
		this->relocationTable.numberOfRelocationBlocks++;
		p += *(PDWORD32)(p + 4); // ָ����һ���ض�λ��
	}
	
	// #3 �����Ӧ�ڴ�����ݽṹ�ڴ�
	this->relocationTable.pRelocationBlockArr = (PRELOCATION_BLOCK)malloc(sizeof(RELOCATION_BLOCK) * this->relocationTable.numberOfRelocationBlocks);
	if (this->relocationTable.pRelocationBlockArr != NULL) {
		errorCode = 2;
		return FALSE;
	}

	// #4 ��ÿ���ض�λ������ɨ��
	p = this->fileBuffer + this->RvaToFoa(this->pOptionalHeader->DataDirectory[5].VirtualAddress); // ��ȡ�ض�λ���ַ
	for (int i = 0; i < this->relocationTable.numberOfRelocationBlocks; i++) {
		this->relocationTable.pRelocationBlockArr[i].numberOfItems = (*(PDWORD32)(p + 4) - 8) / 2; // ������������
		this->relocationTable.pRelocationBlockArr[i].pItemsArr = (PWORD)(p + 8); // �ڴ�ʵ�ָ�ֵ
		p += *(PDWORD32)(p + 4); // ָ����һ���ض�λ��
	}
	return TRUE;
}