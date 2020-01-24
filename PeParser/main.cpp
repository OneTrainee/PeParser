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
	PeParser pe((char*)"C:\\Users\\97905\\Desktop\\AsmHighlight.dll");
	
	// 显示导出函数
	for (int i = 0; i < pe.lengthOfExpoterMemberArr; i++) {
		cout << pe.pExpoterMemberArr[i].index << " "
			<< pe.pExpoterMemberArr[i].funcName << " "
			<< pe.pExpoterMemberArr[i].funcAddr << endl;
	}
	// 写入文件
	//pe.SaveFile((const char*)"C:\\Users\\97905\\Desktop\\CrackMeNew.exe");
	return 0;

}

