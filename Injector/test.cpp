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