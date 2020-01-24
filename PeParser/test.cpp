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