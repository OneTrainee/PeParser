#include "test.h"
#include "PeParser.h"
#include <stdio.h>
#include <iostream>
using namespace std;


void Test_HookEntryPoint() {
/*
@函数作用：测试Hook EntryPoint 是否成功。
@注意事项：
	#1.FOA与RAW的转换存在一些问题，如果对齐不相等，可能会出现计算错误。
	#2.代码注入时，如果调用函数，必须首先自行计算出相对偏移地址，随着学习的深入，可能会出现新的技巧。
*/
	PeParser pe((char*)"C:\\Users\\97905\\Desktop\\CrackMe.exe");
	//33C0
	const char shellCode[] = { 0x33,0xC0,0x33,0xC0,0x33,0xC0 };
	// Hook EntryPoint
	pe.HookEntryPoint(shellCode, sizeof(shellCode));

	// 写入文件
	pe.SaveFile((const char*)"C:\\Users\\97905\\Desktop\\CrackMeNew.exe");
	return ;
}

void Test_InitExportTable() {
/*
@函数作用：测试初始化导出表
*/
	PeParser pe((char*)"C:\\Users\\97905\\Desktop\\AsmHighlight.dll");

	// 显示导出函数

	for (int i = 0; i < pe.lengthOfExpoterMemberArr; i++) {
		cout << pe.pExpoterMemberArr[i].index << " "
			<< pe.pExpoterMemberArr[i].funcName << " "
			<< pe.pExpoterMemberArr[i].funcAddr << endl;
	}

}

void Test_InitImportTable() {
/*
@函数作用：测试导入表是否导入成功。
*/
	PeParser pe((char*)"C:\\Users\\97905\\Desktop\\CrackMe.exe");

	cout << "导入函数表共有:" << pe.importerTotalTable.numberOfImporterTable << "个" << endl;

	for (int i = 0; i < pe.importerTotalTable.numberOfImporterTable; i++) {
		cout << "*****************************" << endl;
		cout << "模块名字:" << pe.importerTotalTable.importerTableArr[i].tableName << "  "
			<< "导入函数共有:" << pe.importerTotalTable.importerTableArr[i].numberOfFunc << "个" << endl;
		for (int j = 0; j < pe.importerTotalTable.importerTableArr[i].numberOfFunc; j++) {
			if (pe.importerTotalTable.importerTableArr[i].pImporterMemberArr[j].recordType == 0) { // 名称导出
				cout << ">>函数名字:" << pe.importerTotalTable.importerTableArr[i].pImporterMemberArr[j].importFuncName << endl;;
			}
			else { // 序号导出
				cout << ">>函数序号:" << pe.importerTotalTable.importerTableArr[i].pImporterMemberArr[j].importFuncIndex << endl;
			}
		}
	}
}