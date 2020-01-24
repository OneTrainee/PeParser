#pragma once
#include <Windows.h>

typedef struct _EXPOTER_MEMBER {
/*
@
*/
	WORD index; // 函数索引号
	char* funcName; // 函数名字
	DWORD funcAddr; // 函数RVA偏移地址 
	
}EXPOTER_MEMBER, * PEXPOTER_MEMBER;

class PeParser
{
/*
@类作用:PE解析器，负责解析PE文件的各种指令
 */
public:
	// 基本函数
	PeParser(const char * filePath); // PE 构造函数
	BOOL SaveFile(const char* filePath); // 保存文件
	BOOL ExtendPeFile(DWORD extendedByteLength); // 扩大pe文件并且重构属性
	
	// 地址变化
	DWORD RvaToFoa(DWORD rvaValue); // 根据RVA获取FOA值 
	DWORD FoaToRva(DWORD foaValue); // 根据FOA获取RVA值
	DWORD VaToRva(DWORD VaValue); // 根据VA获取RVA值
	DWORD RvaToVa(DWORD RvaValue); // 根据RVA获取VA的值

	// 内存|文件 对齐
	DWORD AilgnByFile(DWORD originalValue); // 获取文件对齐后的值 
	DWORD AilgnByMemory(DWORD originalValue); // 获取内存对齐后的值

	// 表操作
	BOOL initExportTable(); // 初始化导出表

	// “节”的操作
	BOOL ExtendLastSection(DWORD extendedByteLength); // 扩大最后一个节
	BOOL AddNewSection(DWORD newSectionLength, const char* newSectionName); // 添加新节
	BOOL MergeDoubleSections(); // 合并两个节

	// 工具
	DWORD SearchEmptyCodeSegmentAddress(int sizeOfCodeSegment); // 在节中搜索可注入地址（如果可以则将该节属性改为可执行 60000020）
	BOOL HookEntryPoint(const char* shellCode, int sizeOfShellCode); // Hook程序入口地址


	//
	// PE成员变量
	//
	PIMAGE_DOS_HEADER pDosHeader; // PE的DOS头
	PIMAGE_NT_HEADERS pNtHeaders; // NT总头
	PIMAGE_FILE_HEADER pFileHeader; // NT文件头
	PIMAGE_OPTIONAL_HEADER pOptionalHeader; // PE可选头
	PIMAGE_SECTION_HEADER pSectionHeaders[20]; // PE节区头(最大为20个）
	PEXPOTER_MEMBER pExpoterMemberArr; // 导出表成员数组
	DWORD lengthOfExpoterMemberArr; // 导出表成员数组的长度
	BOOL alignSign; // 若文件偏移与内存偏移相等则为True
	int errorCode; // 错误码
	/*
	@0:成功
	@1:文件打开失败
	@2:内存申请失败
	@3:PE指纹校验失败
	@4:RvaToFoa计算失败
	@5:FoaToRva计算失败
	@6:PE重新构建失败
	*/
private:
	char * fileBuffer; // PE文件缓存到内存中的地址
	DWORD fileSize; // 文件大小

};

