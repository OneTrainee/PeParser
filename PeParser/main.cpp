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

	// 显示重定位表
	cout << "一共有重定位块：" << pe.relocationTable.numberOfRelocationBlocks << "个" << endl;
	for (int i = 0; i < pe.relocationTable.numberOfRelocationBlocks; i++) {
		cout << "**该块中有重定位项:" << pe.relocationTable.pRelocationBlockArr[i].numberOfItems << "个" << endl;
		for (int j = 0; j < pe.relocationTable.pRelocationBlockArr[i].numberOfItems; j++) {
			printf("<<%x\n", pe.relocationTable.pRelocationBlockArr[i].pItemsArr[j]);
		}
	}
	return 0;

}

