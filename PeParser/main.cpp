// Injector.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "PeParser.h"
using namespace std;

int main()
{
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
	
	return 0;

}

