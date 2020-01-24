#pragma once
#include <Windows.h>

typedef struct _IMPORTER_MEMBER
{
/*
@��: ������Ա
@����: ÿ�����뺯���ľ�������
*/
	DWORD recordType; // ��¼����  [0:��������|1:����]
	char* importFuncName; // ���뺯������
	DWORD importFuncIndex; // ���뺯������
}IMPORTER_MEMBER, * PIMPORTER_MEMBER;

typedef struct _IMPORTER_TABLE {
/*
@���������
@���ã���ʼ��ÿ���ṹ�ĵ����
*/
	char* tableName; // ����
	DWORD numberOfFunc; // ���뺯������
	PIMPORTER_MEMBER pImporterMemberArr; // ���뺯����Ա����
}IMPORTER_TABLE, * PIMPORTER_TABLE;

typedef struct _IMPORTER_TOTAL_TABLE
{
/*
@����������ܱ�
@���ã���¼���ļ�һ���ж��ٸ������͸��������ı���
*/
	PIMPORTER_TABLE importerTableArr; // ���������,��С[0,numberOfImporterTable)
	DWORD numberOfImporterTable; // ����������
}IMPORTER_TOTAL_TABLE,*PIMPORTER_TOTAL_TABLE;


typedef struct _EXPOTER_MEMBER {
/*
@
*/
	WORD index; // ����������
	char* funcName; // ��������
	DWORD funcAddr; // ����RVAƫ�Ƶ�ַ 
	
}EXPOTER_MEMBER, * PEXPOTER_MEMBER;

class PeParser
{
/*
@������:PE���������������PE�ļ��ĸ���ָ��
 */
public:
	// ��������
	PeParser(const char * filePath); // PE ���캯��
	BOOL SaveFile(const char* filePath); // �����ļ�
	BOOL ExtendPeFile(DWORD extendedByteLength); // ����pe�ļ������ع�����
	
	// ��ַ�仯
	DWORD RvaToFoa(DWORD rvaValue); // ����RVA��ȡFOAֵ 
	DWORD FoaToRva(DWORD foaValue); // ����FOA��ȡRVAֵ
	DWORD VaToRva(DWORD VaValue); // ����VA��ȡRVAֵ
	DWORD RvaToVa(DWORD RvaValue); // ����RVA��ȡVA��ֵ

	// �ڴ�|�ļ� ����
	DWORD AilgnByFile(DWORD originalValue); // ��ȡ�ļ�������ֵ 
	DWORD AilgnByMemory(DWORD originalValue); // ��ȡ�ڴ������ֵ

	// �����
	BOOL initExportTable(); // ��ʼ��������
	BOOL initImportTable(); // ��ʼ�������

	// ���ڡ��Ĳ���
	BOOL ExtendLastSection(DWORD extendedByteLength); // �������һ����
	BOOL AddNewSection(DWORD newSectionLength, const char* newSectionName); // ����½�
	BOOL MergeDoubleSections(); // �ϲ�������

	// ����
	DWORD SearchEmptyCodeSegmentAddress(int sizeOfCodeSegment); // �ڽ���������ע���ַ����������򽫸ý����Ը�Ϊ��ִ�� 60000020��
	BOOL HookEntryPoint(const char* shellCode, int sizeOfShellCode); // Hook������ڵ�ַ


	//
	// PE��Ա����
	//
	PIMAGE_DOS_HEADER pDosHeader; // PE��DOSͷ
	PIMAGE_NT_HEADERS pNtHeaders; // NT��ͷ
	PIMAGE_FILE_HEADER pFileHeader; // NT�ļ�ͷ
	PIMAGE_OPTIONAL_HEADER pOptionalHeader; // PE��ѡͷ
	PIMAGE_SECTION_HEADER pSectionHeaders[20]; // PE����ͷ(���Ϊ20����
	PEXPOTER_MEMBER pExpoterMemberArr; // �������Ա����
	IMPORTER_TOTAL_TABLE importerTotalTable; // �����ܱ�(����϶����ڣ���˲���Ҫ��ָ��)
	DWORD lengthOfExpoterMemberArr; // �������Ա����ĳ���
	BOOL alignSign; // ���ļ�ƫ�����ڴ�ƫ�������ΪTrue
	int errorCode; // ������
	/*
	@0:�ɹ�
	@1:�ļ���ʧ��
	@2:�ڴ�����ʧ��
	@3:PEָ��У��ʧ��
	@4:RvaToFoa����ʧ��
	@5:FoaToRva����ʧ��
	@6:PE���¹���ʧ��
	*/



private:
	char * fileBuffer; // PE�ļ����浽�ڴ��еĵ�ַ
	DWORD fileSize; // �ļ���С

};

