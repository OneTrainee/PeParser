#include "test.h"
#include "PeParser.h"
#include <stdio.h>
#include <iostream>
using namespace std;


void Test_HookEntryPoint() {
/*
@�������ã�����Hook EntryPoint �Ƿ�ɹ���
@ע�����
	#1.FOA��RAW��ת������һЩ���⣬������벻��ȣ����ܻ���ּ������
	#2.����ע��ʱ��������ú����������������м�������ƫ�Ƶ�ַ������ѧϰ�����룬���ܻ�����µļ��ɡ�
*/
	PeParser pe((char*)"C:\\Users\\97905\\Desktop\\CrackMe.exe");
	//33C0
	const char shellCode[] = { 0x33,0xC0,0x33,0xC0,0x33,0xC0 };
	// Hook EntryPoint
	pe.HookEntryPoint(shellCode, sizeof(shellCode));

	// д���ļ�
	pe.SaveFile((const char*)"C:\\Users\\97905\\Desktop\\CrackMeNew.exe");
	return ;
}

void Test_InitExportTable() {
/*
@�������ã����Գ�ʼ��������
*/
	PeParser pe((char*)"C:\\Users\\97905\\Desktop\\AsmHighlight.dll");

	// ��ʾ��������

	for (int i = 0; i < pe.lengthOfExpoterMemberArr; i++) {
		cout << pe.pExpoterMemberArr[i].index << " "
			<< pe.pExpoterMemberArr[i].funcName << " "
			<< pe.pExpoterMemberArr[i].funcAddr << endl;
	}

}

void Test_InitImportTable() {
/*
@�������ã����Ե�����Ƿ���ɹ���
*/
	PeParser pe((char*)"C:\\Users\\97905\\Desktop\\CrackMe.exe");

	cout << "���뺯������:" << pe.importerTotalTable.numberOfImporterTable << "��" << endl;

	for (int i = 0; i < pe.importerTotalTable.numberOfImporterTable; i++) {
		cout << "*****************************" << endl;
		cout << "ģ������:" << pe.importerTotalTable.importerTableArr[i].tableName << "  "
			<< "���뺯������:" << pe.importerTotalTable.importerTableArr[i].numberOfFunc << "��" << endl;
		for (int j = 0; j < pe.importerTotalTable.importerTableArr[i].numberOfFunc; j++) {
			if (pe.importerTotalTable.importerTableArr[i].pImporterMemberArr[j].recordType == 0) { // ���Ƶ���
				cout << ">>��������:" << pe.importerTotalTable.importerTableArr[i].pImporterMemberArr[j].importFuncName << endl;;
			}
			else { // ��ŵ���
				cout << ">>�������:" << pe.importerTotalTable.importerTableArr[i].pImporterMemberArr[j].importFuncIndex << endl;
			}
		}
	}
}