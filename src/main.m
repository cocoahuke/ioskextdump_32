//
//  main.m
//  parseDisasmKexts
//
//  Created by huke on 2/25/16.
//  Copyright (c) 2016 com.cocoahuke. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "capstone/capstone.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

NSString *EXPORT_CLASSINFO_FILES_PATH = NULL;
//导出多个整理后的信息文件(需要自己创建目录) 或者作为当作导入的路径

//#define FuzzIOKit_data_path @"/Users/huke/Desktop/fuzz_data/" //导出给Fuzz使用的文件夹位置

//#define FuzzIOKit_phase1_export 0 //第一个数据文件输出,内含KEXT名称和类(FuzzIOKit_data1.plist)

char *__DATA = "__DATA";
//iOS10为__DATA_CONST

BOOL exportMode = 0;

NSMutableDictionary *export_allClass_relation; //所有类之间的继承关系
//Save the all classes address to showinheritance relationship

//NSMutableDictionary *export_cracking_inheritFunc; //所有类的继承关系
//Track the inheritance of a single class



NSMutableDictionary *FuzzIOKit_phase1;

uint32_t r0;
uint32_t r1;
uint32_t r2;
uint32_t r3;
uint32_t r4;
uint32_t r5;
uint32_t r6;
uint32_t r7;
uint32_t r8;

//下面是读取的类信息,来自KEXT_info_export读取出来的
NSDictionary *cracking_inheritFunc; //指定的IO对象继承函数地址
NSDictionary *allClass_relation; //所有类之间的继承关系

//下面是打包的类信息,用于写入文件
NSMutableArray *class_array; //所有类
NSMutableArray *class_newUserClientWithOSDic; //收集信息:重写这个函数的类
NSMutableArray *class_newUserClient; //收集信息:重写这个函数的类
NSMutableDictionary *class_userCleint_methods; //收集信息:客户端类用于externalMethod的函数表

//下面的变量在基础IO类中收集的信息,在这个程序中为全局变量
uint32_t VM_OSMetaClassOSMetaClass; //OSMetaClass::OSMetaClass

uint32_t VM_IOService; //IOService
uint32_t VM_IOUserClient; //IOUserClient


/*ida找IOServicenewUserClientWithOSDic函数技巧,下方的函数是stringFromReturn,卡头就会引用一个字符串"success"*/

uint32_t *IOService_newUserClientWithOSDic; //IOService + 0x244
uint32_t *IOService_newUserClient; //IOService + 0x248

uint32_t *IOUserClient_externalMethod; //IOUserClient + 0x340
uint32_t *IOUserClient_clientMemoryForType; //IOUserClient + 0x368
uint32_t *IOUserClient_getExternalMethodForIndex; //IOUserClient + 0x374
uint32_t *IOUserClient_getTargetAndMethodForIndex; //IOUserClient + 0x37C
uint32_t *IOUserClient_getExternalTrapForIndex; //IOUserClient + 0x384
uint32_t *IOUserClient_getTargetAndTrapForIndex; //IOUserClient + 0x388

//除了基础类函数继承,分析其他的类继承函数,从dic(allClass_relation)读取
NSDictionary *IOHIDEventService_copyEvent; //IOHIDEventService + 0x3C4

struct vtable_func{
    char *func_name;
    uint32_t func_offset;
    uint64_t func_vm;
};

int IOService_vtable_limit = 166;//IOService函数表结束的位置或者IOUserClient_externalMethod-1的位置

struct func_nameAnDoffset{
    int a:5;
};

// - - - 分割线

int isUserClient; //判断当前分析的IO类是否为UserClient类.
int isInKEXTnow; //区分当前在分析内核还是内核扩展

//machoH、文件相关函数
uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t FilegetSize(const char *file_path);

//传入每个KEXT的二进制,返回该KEXT的CFBundleID
char *KextGetBundleID(void *bin);

//获取macho文件的入口,搜集基类信息
void setup_OSMetaClassFunc(const char *kr_path);

//分析内核中的ModInit函数,获取各种基本类信息,对后面分析KEXT有帮助
void AnalysisModInitOfKernel(const char *kr_path);

//分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
void AnalysisModInitOfKEXT(void *bin);

//找出内核二进制中所有有效的内核扩展,并且调用函数开始分析(为解析KEXT的始函数)
void FindKEXTsThenAnalysis(const char *kr_path);

//检查是否为有效的内核扩展,有效的话返回1,无效的话返回0
int checkValidKEXTMachOH(void *bin);

//辨认和解析KEXTs中的跳转块(如果不是R12跳转块,返回-1),返回R12跳转地址(ADD R12,PC ~ BX R12)
uint32_t GetR12JumpFromAnalysis(void* bin,uint64_t tar_VMAddr,uint64_t tar_fileoff);

int32_t getMEMOPoffset(csh handle,const cs_insn *insn); //得到str/ldr指令的内存偏移数
int getMEMOPregister(csh handle,const cs_insn *insn); //得到str/ldr指令的偏移寄存器

int getFirstReg(csh handle,const cs_insn *insn); //得到第一个寄存器
int getSecondReg(csh handle,const cs_insn *insn); //得到第二个寄存器

uint32_t* getActualVarFromRegName(uint64_t address,int RegName); //根据寄存器名字得到对应的变量

int32_t getSingleIMM(csh handle,const cs_insn *insn);//得到单条指令的立即数

void* getMemFromAddrOfVM(void* bin,uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr);//转换汇编的虚拟内存地址,返回在内存中的实际内容

uint64_t getfileoffFromAddrOfVM(uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr);//转换虚拟内存地址,返回文件中偏移地址

uint64_t getPCinThumboffset(uint64_t base,int offset); //计算返回根据thumb指令pc(+2/4)+offset的地址

void ParseConstFunc(char **cn,uint32_t class_self,uint32_t class_super,void *bin,uint64_t VMaddr,uint64_t fileoff);//分析该IO类的函数表等处在_const sec的内容

void find_openType(char *class_name,void *bin,uint64_t newUserClient_vm,uint64_t newUserClient_fileoff);//查找重写了newUserClient的对象中,得到可能的OpenType值

//检查指针指向位置是否在已分配的虚拟内存内,正确返回1
int check_PointerAddrInVM(uint64_t tar_addr);

void AnalysisAllocFunc();//分析Alloc函数,得到vtable

//收集程序的信息的输出宏,按需要使用,以下1为输出,反之为0
#pragma mark define:输出内核对象的信息
#define printInfoOfKernel 1 //如果关掉这个,那么下面的选项对内核对象都不会输出

#pragma mark define:输出对内核对象所收集的地址信息
#define printFuncFinderOfKernel 1 //会输出一些函数地址,用于后面判断内核扩展对象的继承,不受上面所影响

#pragma mark define:输出UserClient类的methods信息
#define printMethodsInfo 1 //输出UserClient类的methods信息

#pragma mark define:在每次分析IO类时输出其归属内核扩展BundleID和序号
#define printKEXTBundleとOR 1 //也可以用于清楚地看清有多少个内核扩展

#pragma mark define:输出IO类注册时BL指令的VM地址
#define printVMAddrOfBL 1 //地址可以用于ida中分析

#pragma mark define:输出IO类注册时进行BL调用时的寄存器
#define printCallMC_r0 1 //输出r0寄存器 该类自己
#define printCallMC_r1 1 //输出r1寄存器 该类名字
#define printCallMC_r2 1 //输出r2寄存器 该类父类
#define printCallMC_r3 1 //输出r3寄存器 该类大小

#pragma mark define:输出每个IO类的vtable起始位置
#define printAddrOfVtable 1 //以IO类自己的地址为开头.后面为IO类函数表

#pragma mark define:输出每个客户端(UserClient)类的methods起始位置
#define printAddrOfMethod 0 //eg.class_name methods table in vm_addr

#pragma mark define:输出每个IO类的MetaClass基础函数位置
#define printMCFunc 0 //比如release,alloc等基础函数位置,alloc为最后一个

#pragma mark define:为继承自IOUserClient的类作标记输出
#define printUserClientTag 0//会从继承类和名字中检查 eg.class_name is from IOUserClient

#pragma mark define:在开始分析IO对象时,输出对象的modInit数量
#define printModInitQt 1//eg.total 1 modInit in kext_bundleID

#pragma mark define:输出str/ldr警告信息
#define printWarnFromStrLdr 0 //输出会包含vm地址,注意不包含内核中的IO类,那些代码已经注释掉了,仅仅会输出内核扩展中的错误,饿;其实大部分时候可以无视这些错误信息

#pragma mark define:输出"没有设置相应的寄存器"警告信息
#define printWarnFromRegDidtSet 0//基本这个信息都是由SP寄存器引起的,当前不考虑栈,所以不影响结果

void initForArrAndDic(); //为收集信息的array或者dictionary初始化

void usage(){
    printf("Usage: ioskextdump_32 [-e] [-p <access directory path>] <kernelcache>\n");
}

int check_file_exist(const char *path){
    if(!access(path,F_OK)){
        if(!access(path,R_OK)){
            return 0;
        }
        return -1;
    }
    return -1;
}

int main(int argc, const char * argv[]) {
    
    if(argc==1){
        printf("wrong args\n");usage();exit(1);
    }
    
    for(int i=0;i<argc;i++){
        if(!strcmp(argv[i],"-h")){
            usage();exit(1);
        }
        if(!strcmp(argv[i],"-e")){
            exportMode = YES;
        }
        if(!strcmp(argv[i],"-p")){
            EXPORT_CLASSINFO_FILES_PATH = (i=i+1)>=argc?nil:[[[NSString stringWithUTF8String:argv[i]] stringByDeletingPathExtension]stringByAppendingString:@"/"];
        }
    }
    
    initForArrAndDic();
    
    const char *ker_path = argv[argc-1];

    if(check_file_exist(ker_path)){
        printf("(%s) kernel cache file is not exist\n",ker_path);exit(1);
    }
    
    if(exportMode)
        export_allClass_relation = [[NSMutableDictionary alloc]init];
    
    setup_OSMetaClassFunc(ker_path);
    AnalysisModInitOfKernel(ker_path);
    FindKEXTsThenAnalysis(ker_path);
    printf("- - - END - - -\n");
    //收集信息结束后,将信息写入文件
    NSLog(@"Total number of IOkit Classes:%lu",(unsigned long)[class_array count]);
    
    /*if(FuzzIOKit_phase1_export){
     [FuzzIOKit_phase1 writeToFile:[FuzzIOKit_data_path stringByAppendingString:@"FuzzIOKit_phase1.plist"] atomically:YES];
     }*/
    
    if(exportMode){
        if([export_allClass_relation writeToFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_relation.plist"] atomically:YES])
            printf("\nallClass_relation.plist saved success\n\n");
        else
            printf("\nallClass_relation.plist writen failed\n\n");
    }
    
    
    //[class_array writeToFile:@"/Desktop/allclass.plist" atomically:YES];
    
    //收集信息
    //[class_newUserClientWithOSDic writeToFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_newUserClientWithOSDic.plist"] atomically:YES];
    //[class_newUserClient writeToFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_newUserClient.plist"] atomically:YES];
    //[class_userCleint_methods writeToFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_userCleint_methods.plist"] atomically:YES];
    //exit(1);
}

//为收集信息的array或者dictionary初始化
#pragma mark imp:为收集信息的array或者dictionary初始化
void initForArrAndDic(){
    FuzzIOKit_phase1 = [[NSMutableDictionary alloc]init];
    NSMutableDictionary *KEXT_INPUT_Mdic = [[NSMutableDictionary alloc]init];
    NSMutableDictionary *KEXT_CLASS_OPENTYPE_Mdic = [[NSMutableDictionary alloc]init];
    [FuzzIOKit_phase1 setObject:KEXT_INPUT_Mdic forKey:@"KEXT_INPUT"];
    [FuzzIOKit_phase1 setObject:KEXT_CLASS_OPENTYPE_Mdic forKey:@"KEXT_CLASS_OPENTYPE"];
    
    //- - - 上面是FuzzIOKit的初始化
    allClass_relation = [NSDictionary dictionaryWithContentsOfFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"class_relation.plist"]];
    //cracking_inheritFunc = [NSDictionary dictionaryWithContentsOfFile:[EXPORT_CLASSINFO_FILES_PATH stringByAppendingString:@"cracking_inheritFunc.plist"]];
    class_array = [[NSMutableArray alloc]init];
    class_newUserClientWithOSDic = [[NSMutableArray alloc]init];
    class_newUserClient = [[NSMutableArray alloc]init];
    class_userCleint_methods = [[NSMutableDictionary alloc]init];
    
    //对指定的IO对象继承的函数变量初始化 供参考
    /*IOHIDEventService_copyEvent = [cracking_inheritFunc objectForKey:@"IOHIDEventService_copyEvent"];
     if(!IOHIDEventService_copyEvent){
     printf("IOHIDEventService_copyEvent is not exist\n");
     exit(1);
     }*/
}


uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        //如果没有sectname,代表该seg的VM起始地址
                        return seg->vmaddr;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        //如果没有sectname,代表该seg的VM起始地址
                        return seg->vmaddr;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    //匹配section
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t FilegetSize(const char *file_path){
    struct stat buf;
    
    if ( stat(file_path,&buf) < 0 )
    {
        perror(file_path);
        exit(1);
    }
    return buf.st_size;
}

//传入每个KEXT的二进制,返回该KEXT的CFBundleID
#pragma mark imp:传入每个KEXT的二进制,返回该KEXT的CFBundleID
char *KextGetBundleID(void *bin){
    uint64_t dataSecStart = machoGetFileAddr(bin,"__DATA","__data");
    uint64_t dataSecSize = machoGetSize(bin,"__DATA","__data");
    
    //printf("\n__DATA is 0x%llx-0x%llx\n",dataSecStart,dataSecStart+dataSecSize);
    
    char mh_Magic[] = {'c','o','m','.'};
    char* per_mh = memmem(bin+dataSecStart,dataSecSize,mh_Magic,0x4);
    if(per_mh){
        return per_mh;
    }
    return "******WRONG_KEXT_NAME******";
}

//imp:获取macho文件的入口,搜集基类信息
#pragma mark imp:获取macho文件的入口,搜集基类信息
//0x90ac3e40
void setup_OSMetaClassFunc(const char *kr_path){
    
    uint8_t firstPage[4096];
    FILE *fp = fopen(kr_path,"ro");
    if(fread(firstPage,1,4096,fp)!=4096){
        printf("read error\n");
        exit(1);
    }
    fclose(fp);
    uint64_t BaseVMAddr = machoGetVMAddr(firstPage,"__TEXT",NULL);
    uint64_t VMAddrOf__DataModInit = machoGetVMAddr(firstPage,"__DATA","__mod_init_func");
    uint64_t fileoffOf__DataModInit = machoGetFileAddr(firstPage,"__DATA","__mod_init_func");
    uint64_t sizeOf__DataModInit = machoGetSize(firstPage,"__DATA","__mod_init_func");
    
    
    FILE *fp_bin = fopen(kr_path,"r");
    void *bin = malloc(fileoffOf__DataModInit+sizeOf__DataModInit); //__mod_init_func的fileoff+size
    if(fread(bin,1,fileoffOf__DataModInit+sizeOf__DataModInit,fp_bin)!=fileoffOf__DataModInit+sizeOf__DataModInit)
        exit(1);
    uint32_t aFuncInit = 0;
    uint32_t VMOSMetaClass = 0;
    memcpy(&aFuncInit,(bin+fileoffOf__DataModInit) + 0x4,4); //__DATA段__mod_init_func的第二行(+4)
    
    if(aFuncInit<=0||aFuncInit>VMAddrOf__DataModInit||aFuncInit<BaseVMAddr){
        printf("setup_OSMetaClassFunc memcpy 获得地址错误\n");
        exit(1);
    }
    
    fclose(fp_bin);
    
    csh handle;
    cs_insn *insn;
    size_t count;
    
    printf("begin to disasm a FuncInit...\n");
    if(cs_open(CS_ARCH_ARM,CS_MODE_THUMB,&handle)!=CS_ERR_OK)
        exit(1);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    int64_t curFunc_FilebaseAddr = aFuncInit-0x1-BaseVMAddr;
    int64_t curFunc_VMbaseAddr = aFuncInit;
    count = cs_disasm(handle,bin+curFunc_FilebaseAddr,0xFFF,curFunc_VMbaseAddr,0,&insn);
    
    size_t j;
    
    for(j=0;j<count;j++){
        if(count > 0){
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            
            if(strstr(insn[j].mnemonic,"bl")){
                printf("try to analysis the info...\n\n");
                int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                if (acount){
                    uint32_t bl_addr = getSingleIMM(handle,&insn[j]);
                    if(bl_addr&&VMOSMetaClass!=0)
                        printf("setup_OSMetaClassFunc aFuncInit 存在多个bl_addr\n");
                    if(bl_addr)
                        VMOSMetaClass = bl_addr-0x1;
                }
            }
            
            if(strstr(insn[j].mnemonic,"pop")){
                //循环到第一个pop处停止
                break;
            }
        }
    }
    cs_free(insn,count);
    VM_OSMetaClassOSMetaClass = VMOSMetaClass;
    free(bin);
    cs_close(&handle);
    printf("OSMetaClass::OSMetaClass -> 0x%x\n\n",VMOSMetaClass);
}

//分析内核中的ModInit函数,获取各种基本类信息,对后面分析KEXT有帮助
#pragma mark imp:分析内核中的ModInit函数,获取各种基本类信息,对后面分析KEXT有帮助
void AnalysisModInitOfKernel(const char *kr_path){
    
    int KR_DEBUG_ENABLE = 0; //1为激活DEBUG,输出每个基础类的信息
    
    if(printInfoOfKernel){
        //うん,这里就直接把控制宏和这个连起来了...
        KR_DEBUG_ENABLE = 1;
    }
    
    csh handle;
    cs_insn *insn = NULL;
    size_t count = 0;
    
    uint64_t kr_size = FilegetSize(kr_path);
    if(kr_size==0){
        printf("FilegetSize Error\n");
        exit(1);
    }
    
    void *kr_bin = malloc(kr_size);
    FILE *fp = fopen(kr_path,"ro");
    if(fread(kr_bin,1,kr_size,fp)!=kr_size){
        printf("read error\n");
        exit(1);
    }
    fclose(fp);
    
    if(cs_open(CS_ARCH_ARM,CS_MODE_THUMB,&handle)!=CS_ERR_OK)
        exit(1);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    uint64_t modInitVM = machoGetVMAddr(kr_bin,"__DATA","__mod_init_func");
    uint64_t modInitFileoff = machoGetFileAddr(kr_bin,"__DATA","__mod_init_func");
    uint64_t modInitSize = machoGetSize(kr_bin,"__DATA","__mod_init_func");
    
    printf("total %llu Kernel base Object modInit\n",modInitSize/4);
    printf("starting try to collect base obj info...\n\n");
    
    for(int ab=1;ab<modInitSize/4;ab++){
        
        uint32_t *eachModInitEntry = getMemFromAddrOfVM(kr_bin,modInitFileoff,modInitVM,modInitVM+ab*4);
        uint64_t eachModInitFileoff = getfileoffFromAddrOfVM(modInitFileoff,modInitVM,*eachModInitEntry);
        
        int64_t curFunc_FilebaseAddr = eachModInitFileoff-1;
        int64_t curFunc_VMbaseAddr = (*eachModInitEntry)-1;
        
        if(KR_DEBUG_ENABLE&&printKEXTBundleとOR)
            printf("\nKEXT_DEBUG:********%d*******\n",ab);
        count = cs_disasm(handle,kr_bin+curFunc_FilebaseAddr,0xfff,curFunc_VMbaseAddr,0,&insn);
        if(count > 0){
            
            size_t j;
            r0 = 0;
            r1 = 0;
            r2 = 0;
            r3 = 0;
            r4 = 0;
            r5 = 0;
            r6 = 0;
            r7 = 0;
            r8 = 0;
            
            char *cn = "";
            uint32_t class_self = 0;
            uint32_t class_super = 0;
            for(j=0;j<count;j++){
#pragma mark KER_DEBUG:KEXT输出汇编
                //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
                
#pragma mark KER_DEBUG:MOV OP
                if(strstr(insn[j].mnemonic,"mov")){
                    int acount = cs_op_count(handle,&insn[j],ARM_OP_REG);
                    if(acount==2){
                        //两个寄存器之间的MOV操作
                        int s_reg = getSecondReg(handle,&insn[j]);
                        if(s_reg==ARM_REG_SP){
                            //暂时忽略sp
                            //printf("MOV--SP寄存器\n");
                            continue;
                        }
                        uint32_t *rx = getActualVarFromRegName(insn[j].address,s_reg);
                        if(!rx)
                            continue;
                        if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                            r0 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                            r1 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                            r2 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                            r3 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                            r4 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                            r5 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                            r6 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                            r7 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                            r8 = *rx;
                        }
                    }
                    else{
                        //MOV一个立即数到寄存器
                        int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                        if(acount>0){
                            uint32_t *rx = NULL;
                            int32_t imm = getSingleIMM(handle,&insn[j]);
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                rx = &r0;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                rx = &r1;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                rx = &r2;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                rx = &r3;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                rx = &r4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                rx = &r5;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                rx = &r6;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                rx = &r7;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                rx = &r8;
                            }
                            if(rx){
                                if(!strcmp(insn[j].mnemonic,"movw")){
#pragma mark KER_DEBUG:MOVW OP
                                    //low 16bit
                                    //uint16_t imm = (uint16_t)getSingleIMM(handle,&insn[j]);
                                    *rx = *rx>>16<<16|(uint32_t)imm;
                                }
                                else if(!strcmp(insn[j].mnemonic,"movt")){
#pragma mark KER_DEBUG:MOVT OP
                                    //high 16bit
                                    //uint16_t imm = (uint16_t)getSingleIMM(handle,&insn[j]);
                                    *rx = (uint32_t)imm<<16|(uint16_t)*rx;
                                }
                                else{
                                    *rx = imm;
                                }
                            }
                        }
                    }
                }
                
#pragma mark KER_DEBUG:ADD OP
                if(strstr(insn[j].mnemonic,"add")){
                    //printf("%s\n\n",insn[j].op_str);
                    int acount = cs_op_count(handle,&insn[j],ARM_OP_REG);
                    if(acount==2){
                        
                        int imm_acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                        if(imm_acount==1){
                            //处理add指令2个寄存器,一个立即数情况
                            int s_reg = getSecondReg(handle,&insn[j]);
                            
                            if(s_reg==ARM_REG_SP)
                                continue; //暂时不涉及栈指针
                            
                            uint32_t *rx = getActualVarFromRegName(insn[j].address,s_reg);
                            if(!rx)
                                continue;
                            uint32_t imm = getSingleIMM(handle,&insn[j]);
                            
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = *rx+imm;
                            }
                        }
                        else if(imm_acount>1){
                            printf("0x%llx add超过2个立即数存在\n",insn[j].address);
                            exit(1);
                        }
                        
                        int s_reg = getSecondReg(handle,&insn[j]);
                        if(s_reg==ARM_REG_PC){
                            //如果第二个寄存器为pc,那么计算原本寄存器内的偏移值.
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = (uint32_t)insn[j].address + r0 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = (uint32_t)insn[j].address + r1 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = (uint32_t)insn[j].address + r2 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = (uint32_t)insn[j].address + r3 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = (uint32_t)insn[j].address + r4 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = (uint32_t)insn[j].address + r5 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = (uint32_t)insn[j].address + r6 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = (uint32_t)insn[j].address + r7 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = (uint32_t)insn[j].address + r8 + 0x4;
                            }
                        }
                        //如果操作了两个寄存器...do
                    }
                    if(acount==1){
                        //add的立即数操作
                        int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                        if (acount){
                            uint32_t imm = getSingleIMM(handle,&insn[j]);
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = r0 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = r1 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = r2 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = r3 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = r4 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = r5 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = r6 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = r7 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = r8 + imm;
                            }
                        }
                    }
                    //如果为add指令...do
                }
                
#pragma mark KER_DEBUG:BL OP
                if(strstr(insn[j].mnemonic,"bl")){
                    //每个mod_initFunc都会有个一个或者多个BL的立即数调用,间接跳转到OSMetaClass:OSMetaClass (待定)
                    int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                    if (acount){
                        uint32_t bl_addr = getSingleIMM(handle,&insn[j]);
                        
                        //检查是否为OSMetaClass
                        if((uint32_t)bl_addr==VM_OSMetaClassOSMetaClass){
                            class_self = r0;
                            class_super = r2;
        
                            if(exportMode){
                                char *add_r1_str = getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,r1);
                                [export_allClass_relation setObject:[NSDictionary dictionaryWithObjects:@[[NSNumber numberWithUnsignedLongLong:class_self],[NSString stringWithFormat:@"%s",add_r1_str],[NSNumber numberWithUnsignedInt:r2],[NSNumber numberWithUnsignedInt:r3]] forKeys:@[@"class_self",@"class_name",@"class_super",@"class_size"]] forKey:[NSString stringWithFormat:@"0x%x",r0]];
                            }
                            
                            if(KR_DEBUG_ENABLE){
                                if(printVMAddrOfBL)
                                    printf("(0x%llx)->OSMetaClass:OSMetaClass call 4 args list\n",insn[j].address);
                                if(printCallMC_r0)
                                    printf("r0:0x%x\n",r0);
                            }
                            if(r1==0){
                                if(KR_DEBUG_ENABLE)
                                    if(printCallMC_r1)
                                        printf("r1:0x%x\n",r1);
                                cn = "unknow classname";
                            }else{
                                char *r1_str = getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,r1);
                                if(KR_DEBUG_ENABLE&&printCallMC_r1)
                                    printf("r1:%s\n",r1_str);
                                cn = r1_str; //记录类名.待后面查找vtable(kr代码先留着)
                                
                                //下面部分用来搜集类信息,添加代码在下面
                                if(strcmp(r1_str,"IOUserClient")==0){
                                    VM_IOUserClient = r0;
                                    printf("\nIOUserClient -> 0x%x\n",r0);
                                }
                                if(strcmp(r1_str,"IOService")==0){
                                    VM_IOService = r0;
                                    printf("\nIOService -> 0x%x\n",r0);
                                }
                                //= = =划分线
                            }
                            if(KR_DEBUG_ENABLE){
                                if(printCallMC_r2)
                                    printf("r2:0x%x\n",r2);
                                if(printCallMC_r3)
                                    printf("r3:0x%x\n",r3);
                            }
                        }
                        
                        //printf("r0:0x%x\nr1:0x%x\nr2:0x%x\nr3:0x%x\n\n",r0,r1,r2,r3);
                        //printf("r0:0x%x\n",r1);
                    }
                }
                
#pragma mark KER_DEBUG:LDR OP
                int acount = cs_op_count(handle,&insn[j],ARM_OP_MEM);
                if (acount) {
                    //printf("\timm_count: %u\n",acount);
                    if(strstr(insn[j].mnemonic,"ldr")){
                        int offset = getMEMOPoffset(handle,&insn[j]);
                        int reg = getMEMOPregister(handle,&insn[j]);
                        
                        if(reg!=ARM_REG_PC&&offset!=0){
                            //printf("0x%llx ldr 指令会涉及到相对寄存器偏移处,对此情况未作分析,请手动分析\n",insn[j].address);
                            //对于OSMetaClass的调用没有影响
                            continue;
                        }
                        
                        if(reg==ARM_REG_PC){
                            //计算pc和其偏移,将计算结果指向的内存拷贝到寄存器
                            //eg. ldr r1,[pc,#0x48]
                            uint64_t addr = getPCinThumboffset(insn[j].address,offset);
                            int32_t data;
                            memcpy(&data,getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,addr),4);
                            //printf("%s 0x%llx #0x%x\n\n",insn[j].op_str,addr,data);
                            //printf("aaa %s\n",insn[j].op_str);
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = data;
                            }
                            //printf("%s + 0x%x #0x%llx\n\n",cs_reg_name(handle,reg),offset,addr);
                        }
                        int imm_acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                        //imm_acount是过滤掉了ldr [r8[,#4的这种情况
                        if(offset==0&&!imm_acount&&reg!=ARM_REG_PC){
                            //ldr指令将第二个寄存器指向的内存拷贝到第一个寄存器值
                            //eg. ldr r2,[r3]
                            int reg = getMEMOPregister(handle,&insn[j]);
                            
                            uint32_t *rx = getActualVarFromRegName(insn[j].address,reg);
                            if(!rx)
                                continue;
                            uint32_t *mem = getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,*rx);
                            
                            if(!check_PointerAddrInVM((uint64_t)mem)){
                                printf("0x%llx pointer was point to outside of virtual memory, skip analysis this command\n",insn[j].address);
                                continue;
                            }
                            
                            if(!mem){
                                printf("ldr 无法找到指定位置的内存\n");
                                exit(1);
                            }
                            
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = *mem;
                            }
                            
                        }
                    }
                    else if(strstr(insn[j].mnemonic,"str")){
#pragma mark KER_DEBUG:STR OP
                        //str指令将第一个寄存器值拷贝到另一个寄存器指向的内存
                        //eg. str r1,[r0]
                        int offset = getMEMOPoffset(handle,&insn[j]);
                        if(offset<=0)
                            offset = 0;
                        
                        int reg = getMEMOPregister(handle,&insn[j]);
                        
                        uint32_t *rx = getActualVarFromRegName(insn[j].address,reg);
                        if(!rx)
                            continue;
                        
                        uint64_t targ_cur = 0;
                        
                        
                        if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                            targ_cur = r0;
                        }
                        if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                            targ_cur = r1;
                        }
                        if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                            targ_cur = r2;
                        }
                        if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                            targ_cur = r3;
                        }
                        if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                            targ_cur = r4;
                        }
                        if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                            targ_cur = r5;
                        }
                        if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                            targ_cur = r6;
                        }
                        if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                            targ_cur = r7;
                        }
                        if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                            targ_cur = r8;
                        }
                        
                        if(targ_cur<machoGetVMAddr(kr_bin,"__TEXT",NULL)){
                            //即第一个寄存器指向的vm地址不在可执行文件的范围内
                            continue;
                        }
                        
                        ParseConstFunc(&cn,class_self,class_super,kr_bin,targ_cur,getfileoffFromAddrOfVM(curFunc_FilebaseAddr,curFunc_VMbaseAddr,targ_cur));
                        
                        uint32_t *mem = getMemFromAddrOfVM(kr_bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,(*rx + offset));
                        
                        if(!check_PointerAddrInVM((uint64_t)mem)){
                            printf("0x%llx pointer was point to outside of virtual memory, skip analysis this command\n",insn[j].address);
                            continue;
                        }
                        
                        if(mem)
                            *mem = (uint32_t)targ_cur; //修改第二个寄存器指向内存处
                        else{
                            printf("str 无法找到指定位置的内存\n");
                            exit(1);
                        }
                        //printf("result:0x%x\n",*mem);
                    }
                }
#pragma mark KER_DEBUG:POP OP
                if(strstr(insn[j].mnemonic,"pop")){
                    //到pop指令处停止
                    break;
                }
                
                //printf("%s\n\n",insn[j].op_str);
            }
            cs_free(insn,count);
        }
        else{
            printf("ERROR: Failed to disassemble given code!\n");
        }
    }
    free(kr_bin);
    cs_close(&handle);
}

//分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
#pragma mark imp:分析每个内核扩展中的ModInit函数,主要的分析汇编代码的函数
void AnalysisModInitOfKEXT(void *bin){
    int KEXT_PRINT_EACH_CLASS_INFO = 1;
    isInKEXTnow = 1;
    csh handle;
    cs_insn *insn;
    size_t count;
    
    if(cs_open(CS_ARCH_ARM,CS_MODE_THUMB,&handle)!=CS_ERR_OK){
        printf("AnalysisModInitOfKEXT cs_open出错\n");
        exit(1);
    }
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    uint64_t modInitVM = machoGetVMAddr(bin,"__DATA","__mod_init_func");
    uint64_t modInitFileoff = machoGetFileAddr(bin,"__DATA","__mod_init_func");
    uint64_t modInitSize = machoGetSize(bin,"__DATA","__mod_init_func");
    
    //printf("该内核扩展vm范围:0x%llx-0x%llx\n",KEXT_vmStart,KEXT_vmEnd);
    
    if(printModInitQt)
        printf("\ntotal %llu modInit in %s\n",modInitSize/4,KextGetBundleID(bin)); //will 修改
    //printf("starting check each class...\n\n");
    
    for(int ab=0;ab<modInitSize/4;ab++){
        
        uint32_t *eachModInitEntry = getMemFromAddrOfVM(bin,modInitFileoff,modInitVM,modInitVM+ab*4);
        uint64_t eachModInitFileoff = getfileoffFromAddrOfVM(modInitFileoff,modInitVM,*eachModInitEntry);
        
        int64_t curFunc_FilebaseAddr = eachModInitFileoff-1;//0x107c //0x278c //0x186b4
        int64_t curFunc_VMbaseAddr = (*eachModInitEntry)-1;//0x90caa07c //0x90cab78c //0x90cc16b4
        
        if(KEXT_PRINT_EACH_CLASS_INFO&&printKEXTBundleとOR)
            printf("\n******** %d:%s *******\n",ab,KextGetBundleID(bin));
        count = cs_disasm(handle,bin+curFunc_FilebaseAddr,0xfff,curFunc_VMbaseAddr,0,&insn);
        if(count > 0){
            size_t j;
            r0 = 0;
            r1 = 0;
            r2 = 0;
            r3 = 0;
            r4 = 0;
            r5 = 0;
            r6 = 0;
            r7 = 0;
            r8 = 0;
            
            char *cn = "";
            uint32_t class_self = 0;
            uint32_t class_super = 0;
            for(j=0;j<count;j++){
#pragma mark KEXT_DEBUG:输出汇编
                //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
                //printf("r0:0x%x r1:0x%x r2:0x%x r3:0x%x\n",r0,r1,r2,r3);
                
#pragma mark KEXT_DEBUG:MOV OP
                if(strstr(insn[j].mnemonic,"mov")){
                    
                    int acount = cs_op_count(handle,&insn[j],ARM_OP_REG);
                    if(acount==2){
                        //两个寄存器之间的MOV操作
                        int s_reg = getSecondReg(handle,&insn[j]);
                        if(s_reg==ARM_REG_SP){
                            //暂时忽略sp
                            //printf("MOV--SP寄存器\n");
                            continue;
                        }
                        uint32_t *rx = getActualVarFromRegName(insn[j].address,s_reg);
                        if(!rx)
                            continue;
                        if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                            r0 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                            r1 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                            r2 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                            r3 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                            r4 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                            r5 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                            r6 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                            r7 = *rx;
                        }
                        if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                            r8 = *rx;
                        }
                    }
                    else{
                        //MOV一个立即数到寄存器
                        int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                        if(acount>0){
                            uint32_t *rx = NULL;
                            int32_t imm = getSingleIMM(handle,&insn[j]);
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                rx = &r0;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                rx = &r1;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                rx = &r2;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                rx = &r3;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                rx = &r4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                rx = &r5;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                rx = &r6;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                rx = &r7;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                rx = &r8;
                            }
                            if(rx){
                                if(!strcmp(insn[j].mnemonic,"movw")){
#pragma mark KEXT_DEBUG:MOVW OP
                                    //low 16bit
                                    //uint16_t imm = (uint16_t)getSingleIMM(handle,&insn[j]);
                                    *rx = *rx>>16<<16|(uint32_t)imm;
                                }
                                else if(!strcmp(insn[j].mnemonic,"movt")){
#pragma mark KEXT_DEBUG:MOVT OP
                                    //high 16bit
                                    //uint16_t imm = (uint16_t)getSingleIMM(handle,&insn[j]);
                                    *rx = (uint32_t)imm<<16|(uint16_t)*rx;
                                }
                                else{
                                    *rx = imm;
                                }
                            }
                        }
                    }
                }
                
#pragma mark KEXT_DEBUG:ADD OP
                if(strstr(insn[j].mnemonic,"add")){
                    //printf("%s\n\n",insn[j].op_str);
                    int acount = cs_op_count(handle,&insn[j],ARM_OP_REG);
                    if(acount==2){
                        
                        int imm_acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                        if(imm_acount==1){
                            //处理add指令2个寄存器,一个立即数情况
                            int s_reg = getSecondReg(handle,&insn[j]);
                            
                            if(s_reg==ARM_REG_SP)
                                continue; //暂时不涉及栈指针
                            
                            uint32_t *rx = getActualVarFromRegName(insn[j].address,s_reg);
                            if(!rx)
                                continue;
                            uint32_t imm = getSingleIMM(handle,&insn[j]);
                            
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = *rx+imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = *rx+imm;
                            }
                        }
                        else if(imm_acount>1){
                            printf("0x%llx add超过2个立即数存在\n",insn[j].address);
                            exit(1);
                        }
                        
                        int s_reg = getSecondReg(handle,&insn[j]);
                        if(s_reg==ARM_REG_PC){
                            //如果第二个寄存器为pc,那么计算原本寄存器内的偏移值.
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = (uint32_t)insn[j].address + r0 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = (uint32_t)insn[j].address + r1 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = (uint32_t)insn[j].address + r2 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = (uint32_t)insn[j].address + r3 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = (uint32_t)insn[j].address + r4 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = (uint32_t)insn[j].address + r5 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = (uint32_t)insn[j].address + r6 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = (uint32_t)insn[j].address + r7 + 0x4;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = (uint32_t)insn[j].address + r8 + 0x4;
                            }
                        }
                        //如果操作了两个寄存器...do
                    }
                    if(acount==1){
                        //add的立即数操作
                        int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                        if (acount){
                            uint32_t imm = getSingleIMM(handle,&insn[j]);
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = r0 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = r1 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = r2 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = r3 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = r4 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = r5 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = r6 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = r7 + imm;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = r8 + imm;
                            }
                        }
                    }
                    //如果为add指令...do
                }
                
#pragma mark KEXT_DEBUG:BL OP
                if(strstr(insn[j].mnemonic,"bl")){
                    //printf("当前内核扩展的启示地址:0x%x\n",);
                    //每个mod_initFunc都会有个一个或者多个BL的立即数调用,间接跳转到OSMetaClass:OSMetaClass (待定)
                    int acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                    if (acount){
                        uint32_t bl_addr = getSingleIMM(handle,&insn[j]);
                        
                        uint64_t bl_fileoff = getfileoffFromAddrOfVM(curFunc_FilebaseAddr,curFunc_VMbaseAddr,bl_addr);
                        
                        uint32_t r12FuncCall = GetR12JumpFromAnalysis(bin,bl_addr,bl_fileoff);
                        
                        if(r12FuncCall)
                            r12FuncCall = r12FuncCall - 0x1;
                        
                        bl_addr = bl_addr - 1;
                        
                        isUserClient = 0;
                        //检查是否为OSMetaClass
                        if((uint32_t)r12FuncCall==VM_OSMetaClassOSMetaClass){
                            if(KEXT_PRINT_EACH_CLASS_INFO){
                                if(printVMAddrOfBL)
                                    printf("(0x%llx)->OSMetaClass:OSMetaClass call 4 args list\n",insn[j].address);
                                class_self = r0;
                                class_super = r2;
                                if(printCallMC_r0)
                                    printf("r0:0x%x\n",r0);
                                if(exportMode){
                                    char *add_r1_str = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,r1);
                                    [export_allClass_relation setObject:[NSDictionary dictionaryWithObjects:@[[NSNumber numberWithUnsignedLongLong:class_self],[NSString stringWithFormat:@"%s",add_r1_str],[NSNumber numberWithUnsignedInt:r2],[NSNumber numberWithUnsignedInt:r3]] forKeys:@[@"class_self",@"class_name",@"class_super",@"class_size"]] forKey:[NSString stringWithFormat:@"0x%x",r0]];
                                }
                            }
                            if(r1==0){
                                if(KEXT_PRINT_EACH_CLASS_INFO&&printCallMC_r1)
                                    printf("r1:0x%x\n",r1);
                                cn = "unknow classname";
                            }else{
                                char *r1_str = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,r1);
                                [class_array addObject:[NSString stringWithFormat:@"%s",r1_str]];
                                if(KEXT_PRINT_EACH_CLASS_INFO&&printCallMC_r1)
                                    printf("r1:%s\n",r1_str);
                                
                                //添加更多基类信息,添加代码在下面
                                if(r2==VM_IOUserClient||strstr(r1_str,"UserClient")){
                                    isUserClient = 1;
                                    if(printUserClientTag)
                                        printf("%s is from IOUserClient\n",(char*)r1_str);
                                }
                                
                                //= = = 划分线
                                cn = r1_str; //记录类名.待后面查找vtable
                            }
                            if(KEXT_PRINT_EACH_CLASS_INFO){
                                if(printCallMC_r2)
                                    printf("r2:0x%x\n",r2);
                                char *r1_str = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,r1);
                                if(strstr(r1_str,"UserClient")){
                                    
                                    if(printCallMC_r3&&r3>0x80&&r3<=0xC0)
                                        printf("r3:0x%x\n",r3);
                                    
                                }
                                
                            }
                        }
                        
                        //printf("r0:0x%x\nr1:0x%x\nr2:0x%x\nr3:0x%x\n\n",r0,r1,r2,r3);
                        //printf("r0:0x%x\n",r1);
                    }
                }
                
                
                int acount = cs_op_count(handle,&insn[j],ARM_OP_MEM);
                if (acount) {
                    //printf("\timm_count: %u\n",acount);
                    if(strstr(insn[j].mnemonic,"ldr")){
#pragma mark KEXT_DEBUG:LDR OP
                        //ldr指令将第二个寄存器指向的内存读取到第一个寄存器值
                        //eg. ldr r2,[r3]
                        int offset = getMEMOPoffset(handle,&insn[j]);
                        int reg = getMEMOPregister(handle,&insn[j]);
                        
                        if(reg!=ARM_REG_PC&&offset!=0){
                            if(printWarnFromStrLdr)
                                printf("0x%llx ldr 指令会涉及到相对寄存器偏移处,对此情况未作分析,请手动分析\n",insn[j].address);
                            continue;
                        }
                        
                        if(reg==ARM_REG_PC){
                            //计算pc和其偏移,将计算结果指向的内存拷贝到寄存器
                            //eg. ldr r1,[pc,#0x48]
                            uint64_t addr = getPCinThumboffset(insn[j].address,offset);
                            int32_t data;
                            memcpy(&data,getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,addr),4);
                            //printf("%s 0x%llx #0x%x\n\n",insn[j].op_str,addr,data);
                            //printf("aaa %s\n",insn[j].op_str);
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = data;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = data;
                            }
                            //printf("%s + 0x%x #0x%llx\n\n",cs_reg_name(handle,reg),offset,addr);
                        }
                        int imm_acount = cs_op_count(handle,&insn[j],ARM_OP_IMM);
                        //imm_acount是过滤掉了ldr [r8[,#4的这种情况
                        if(offset==0&&!imm_acount&&reg!=ARM_REG_PC){
                            int reg = getMEMOPregister(handle,&insn[j]);
                            
                            uint32_t *rx = getActualVarFromRegName(insn[j].address,reg);
                            if(!rx)
                                continue;
                            
                            uint32_t *mem = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,*rx);
                            
                            if(!check_PointerAddrInVM((uint64_t)mem)){
                                printf("0x%llx pointer was point to outside of virtual memory, skip analysis this command\n",insn[j].address);
                                continue;
                            }
                            
                            if(!mem){
                                printf("ldr 无法找到指定位置的内存\n");
                                exit(1);
                            }
                            
                            if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                                r0 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                                r1 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                                r2 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                                r3 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                                r4 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                                r5 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                                r6 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                                r7 = *mem;
                            }
                            if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                                r8 = *mem;
                            }
                            
                        }
                    }
                    else if(strstr(insn[j].mnemonic,"str")){
#pragma mark KEXT_DEBUG:STR OP
                        //str指令将第一个寄存器值拷贝到另一个寄存器指向的内存
                        //eg. str r1,[r0]
                        int offset = getMEMOPoffset(handle,&insn[j]);
                        if(offset>=0)
                            offset = 0;
                        
                        int reg = getMEMOPregister(handle,&insn[j]); //sec_reg:r0
                        uint32_t *rx = getActualVarFromRegName(insn[j].address,reg);
                        if(!rx)
                            continue;
                        uint64_t targ_cur = 0;
                        
                        
                        if(memcmp((char*)insn[j].op_str,"r0",2)==0){
                            targ_cur = r0;
                        }
                        if(memcmp((char*)insn[j].op_str,"r1",2)==0){
                            targ_cur = r1;
                        }
                        if(memcmp((char*)insn[j].op_str,"r2",2)==0){
                            targ_cur = r2;
                        }
                        if(memcmp((char*)insn[j].op_str,"r3",2)==0){
                            targ_cur = r3;
                        }
                        if(memcmp((char*)insn[j].op_str,"r4",2)==0){
                            targ_cur = r4;
                        }
                        if(memcmp((char*)insn[j].op_str,"r5",2)==0){
                            targ_cur = r5;
                        }
                        if(memcmp((char*)insn[j].op_str,"r6",2)==0){
                            targ_cur = r6;
                        }
                        if(memcmp((char*)insn[j].op_str,"r7",2)==0){
                            targ_cur = r7;
                        }
                        if(memcmp((char*)insn[j].op_str,"r8",2)==0){
                            targ_cur = r8;
                        }
                        
                        if(targ_cur<machoGetVMAddr(bin,"__TEXT",NULL)){
                            //即第一个寄存器指向的vm地址不在可执行文件的范围内
                            continue;
                        }
                        
                        ParseConstFunc(&cn,class_self,class_super,bin,targ_cur,getfileoffFromAddrOfVM(curFunc_FilebaseAddr,curFunc_VMbaseAddr,targ_cur));
                        
                        uint32_t *mem = getMemFromAddrOfVM(bin,curFunc_FilebaseAddr,curFunc_VMbaseAddr,(*rx + offset));
                        
                        if(!check_PointerAddrInVM((uint64_t)mem)){
                            printf("0x%llx pointer was point to outside of virtual memory, skip analysis this command\n",insn[j].address);
                            continue;
                        }
                        
                        if(mem)
                            *mem = (uint32_t)targ_cur; //修改第二个寄存器指向内存处
                        else{
                            printf("str 无法找到指定位置的内存\n");
                            exit(1);
                        }
                        //printf("result:0x%x\n",*mem);
                    }
                }
                
                if(strstr(insn[j].mnemonic,"pop")){
#pragma mark KEXT_DEBUG:POP OP
                    //到pop指令处停止
                    break;
                }
                
                if(strstr(insn[j].mnemonic,"b.w")){
#pragma mark KEXT_DEBUG:B OP
                    //到b.w指令处停止
                    //这个检查只有在KEXT有.内核中的类不需要
                    //printf("有b指令!!!\n");
                    break;
                }
                
                //printf("%s\n\n",insn[j].op_str);
            }
            cs_free(insn,count);
        }
        else{
            printf("ERROR: Failed to disassemble given code!\n");
        }
    }
    cs_close(&handle);
}

//找出内核二进制中所有有效的内核扩展,并且调用函数开始分析(为解析KEXT的始函数)
#pragma mark imp:找出内核二进制中所有有效的内核扩展,并且调用函数开始分析(为解析KEXT的始函数)
void FindKEXTsThenAnalysis(const char *kr_path){
    uint64_t kr_size = FilegetSize(kr_path);
    if(kr_size==0){
        printf("FilegetSize Error\n");
        exit(1);
    }
    
    void *kr_bin = malloc(kr_size);
    FILE *fp = fopen(kr_path,"ro");
    if(fread(kr_bin,1,kr_size,fp)!=kr_size){
        printf("read error\n");
        exit(1);
    }
    fclose(fp);
    
    uint64_t fileoff = machoGetFileAddr(kr_bin,"__PRELINK_TEXT",NULL);
    uint64_t filesize = machoGetSize(kr_bin,"__PRELINK_TEXT",NULL);
    uint64_t vmoff = machoGetVMAddr(kr_bin,"__PRELINK_TEXT",NULL);
    
    if(fileoff==0||filesize==0||vmoff==0){
        printf("FindKEXTsThenAnalysis 内核二进制__PRELINK_TEXT信息错误\n");
        exit(1);
    }
    
    char mh_Magic[] = {0xce,0xfa,0xed,0xfe};
    uint64_t per_mh = (uint64_t)memmem(kr_bin+fileoff,filesize,mh_Magic,0x4);
    
    int i = 0;
    //real_kext = 0;
    while(1) {
        if(!per_mh)
            break;
        if(checkValidKEXTMachOH((void*)per_mh)){
            //下面的是经过检查后正确的内核扩展KEXTs(添加处理代码加在下面,比如名字过滤)
            char *kext_id = KextGetBundleID((void*)per_mh);
#pragma mark KEXT_LIST:列出所有内核扩展(添加过滤信息)
            
            uint64_t kext_start = machoGetVMAddr((void*)per_mh,"__TEXT",NULL);
            uint64_t kext_end = machoGetVMAddr((void*)per_mh,"__LINKEDIT",NULL) + machoGetSize((void*)per_mh,"__LINKEDIT",NULL);
            printf("%d.0x%llx - 0x%llx %s\n",i,kext_start,kext_end,kext_id);
            
            //printf("%d.macho:0x%llx %s\n",i,per_mh,kext_id);
            //if(!strcmp(kext_id,"com.apple.iokit.IOHIDFamily"))
            AnalysisModInitOfKEXT(per_mh);
            //= = = 分割线
            i++;
        }
        //printf("%d: per_mh is 0x%llx,",i,per_mh);
        //printf("per_mh+4: 0x%llx, per_size: 0x%llx\n",per_mh+4,filesize-(per_mh-(uint64_t)seg_kexts+4));
        per_mh = (uint64_t)memmem((const void *)per_mh+4,filesize-((uint64_t)per_mh-(uint64_t)(kr_bin+fileoff)+4),mh_Magic,0x4);
    }
}

//检查是否为有效的内核扩展,有效的话返回1,无效的话返回0
#pragma mark imp:检查是否为有效的内核扩展,有效的话返回1,无效的话返回0
int checkValidKEXTMachOH(void *bin){
    struct mach_header *mh = (struct mach_header*)bin;
    
    //判断32还是64
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        //printf("it's 32 bit mach-o file\n");
        
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        printf("it's 64 bit mach-o file\n");
        //当前这个程序只适用于32内核二进制
        exit(1);
    }
    if(mh->flags!=1){
        //根据flags判断是否有效
        return 0;
    }
    
    uint64_t check_initFunc = machoGetVMAddr((void*)mh,"__DATA","__mod_init_func");
    if(check_initFunc==-1){
        //检查是否有类信息保存在__mod_init_func
        return 0;
    }
    
    return 1;
}

//辨认和解析KEXTs中的跳转块(如果不是R12跳转块,返回-1),返回R12跳转地址(ADD R12,PC ~ BX R12)
#pragma mark imp:辨认和解析KEXTs中的跳转块(如果不是R12跳转块,返回-1),返回R12跳转地址(ADD R12,PC ~ BX R12)
uint32_t GetR12JumpFromAnalysis(void* bin,uint64_t tar_VMAddr,uint64_t tar_fileoff){
    
    //一般的跳转结构
    /*movw       ip, #0x6740
     movt       ip, #0x0
     add        ip, pc
     ldr.w      ip, [ip]
     bx         ip*/
    
    //下面没有写ldr的分析,取而代之的是(instead),直接在bx指令里得到ip指向的地址,但添加了判断,如果无效指针会是程序退出
    //在64为版本中已添加ldr的分析
    
    csh handle;
    cs_insn *insn;
    size_t count;
    
    if(cs_open(CS_ARCH_ARM,CS_MODE_THUMB,&handle)!=CS_ERR_OK)
        exit(1);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle,bin+tar_fileoff,0xFFF,tar_VMAddr,0,&insn);
    //printf("bin+tar_fileoff = 0x%llx\n",bin+tar_fileoff);
    size_t j;
    
    uint32_t ip = 0;
    
    for(j=0;j<count;j++){
        if(count > 0){
            
            //printf("0x%"PRIX64":\t%s\t\t%s\n",insn[j].address,insn[j].mnemonic,insn[j].op_str);
            
            
            if(j==0){
                //判断第一行
                if(strstr(insn[j].mnemonic,"mov")){
                    int f_reg = getFirstReg(handle,&insn[j]);
                    if(f_reg!=ARM_REG_IP){
                        cs_free(insn,count);
                        cs_close(&handle);
                        return 0;
                    }
                }
                else{
                    cs_free(insn,count);
                    cs_close(&handle);
                    return 0;
                }
            }
            
            if(strstr(insn[j].mnemonic,"mov")){
                
                if(!strcmp(insn[j].mnemonic,"movw")){
                    //low 16bit
                    uint16_t imm = (uint16_t)getSingleIMM(handle,&insn[j]);
                    ip = ip>>16<<16|(uint32_t)imm;
                }
                
                if(!strcmp(insn[j].mnemonic,"movt")){
                    //high 16bit
                    uint16_t imm = (uint16_t)getSingleIMM(handle,&insn[j]);
                    ip = (uint32_t)imm<<16|(uint16_t)ip;
                }
            }
            
            if(strstr(insn[j].mnemonic,"add")){
                //printf("%s\n\n",insn[j].op_str);
                int acount = cs_op_count(handle,&insn[j],ARM_OP_REG);
                if(acount==2){
                    int s_reg = getSecondReg(handle,&insn[j]);
                    if(s_reg==ARM_REG_PC){
                        //如果第二个寄存器为pc,那么计算原本寄存器内的偏移值.
                        if(memcmp((char*)insn[j].op_str,"ip",2)==0){
                            ip = (uint32_t)insn[j].address + ip + 0x4;
                        }
                    }
                }
            }
            
            if(strstr(insn[j].mnemonic,"bx")){
                
                //rr = (uint32_t)g<<16|(uint16_t)rr; //set high 16bit in 32_t
                //rr = rr>>16<<16|(uint32_t)g; //set low 16bit in 32_t
                
                //rr = (uint32_t)g<<16|(uint32_t)d; //2 16b to 32bit
                //printf("32:0x%x 16:0x%x\n",rr,g);
                //printf("ip is 0x%x\n",ip);
                
                int acount = cs_op_count(handle,&insn[j],ARM_OP_REG);
                if (acount==1){
                    int i,ipIF;
                    for (i = 1; i < acount + 1;i++) {
                        int index = cs_op_index(handle,insn,ARM_OP_REG,i);
                        ipIF = insn[j].detail->arm.operands[index].reg;
                        if(ipIF==ARM_REG_IP){
                            uint32_t *data = getMemFromAddrOfVM(bin,tar_fileoff,tar_VMAddr,ip);
                            //printf("a:0x%x b:0x%x\n\n",*data,tar_VMAddr);
                            
                            if(!check_PointerAddrInVM((uint64_t)data)){
                                printf("0x%llx GetR12JumpFromAnalysis:pointer was point to outside of virtual memory, skip analysis this command\n",insn[j].address);
                                exit(1);
                            }
                            cs_free(insn,count);
                            cs_close(&handle);
                            if(data){
                                return *data;
                            }
                        }
                    }
                }
            }
            
            if(strstr(insn[j].mnemonic,"bx")){
                //循环到第一个bx处停止
                break;
            }
        }
    }
    cs_free(insn,count);
    cs_close(&handle);
    return 0;
}

//得到str/ldr指令的内存偏移数
#pragma mark imp:得到str/ldr指令的内存偏移数
int getMEMOPoffset(csh handle,const cs_insn *insn){
    int i,offset;
    int acount = cs_op_count(handle,insn,ARM_OP_MEM);
    if (acount) {
        if(acount>1)
            printf("getMEMOPoffset 多个偏移量\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,ARM_OP_MEM,i);
            offset = insn->detail->arm.operands[index].mem.disp;
            return offset;
        }
    }
    return 0;
}

//得到str/ldr指令的偏移寄存器
#pragma mark imp:得到str/ldr指令的偏移寄存器
int getMEMOPregister(csh handle,const cs_insn *insn){
    int i,offset;
    int acount = cs_op_count(handle,insn,ARM_OP_MEM);
    if (acount) {
        if(acount>1)
            printf("getMEMOPregister 多个偏移量\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,ARM_OP_MEM,i);
            offset = insn->detail->arm.operands[index].mem.base;
            return offset;
        }
    }
    return 0;
}

//得到单条指令的立即数
#pragma mark imp:得到单条指令的立即数
int32_t getSingleIMM(csh handle,const cs_insn *insn){
    int i,imm;
    int acount = cs_op_count(handle,insn,ARM_OP_IMM);
    if (acount) {
        if(acount>1)
            printf("getSingleIMM 多个立即数\n");
        for (i = 1; i < acount + 1;/*i++*/) {
            int index = cs_op_index(handle,insn,ARM_OP_IMM,i);
            imm = insn->detail->arm.operands[index].imm;
            return imm;
        }
    }
    return 0;
}

//得到第一个寄存器
#pragma mark imp:得到第一个寄存器
int getFirstReg(csh handle,const cs_insn *insn){
    int i,s_reg;
    int acount = cs_op_count(handle,insn,ARM_OP_REG);
    if (acount) {
        for (i = 1; i < acount + 1;i++) {
            int index = cs_op_index(handle,insn,ARM_OP_REG,i);
            if(i==1){
                s_reg = insn->detail->arm.operands[index].reg;
                return s_reg;
            }
        }
    }
    return 0;
}

//得到第二个寄存器
#pragma mark imp:得到第二个寄存器
int getSecondReg(csh handle,const cs_insn *insn){
    int i,s_reg;
    int acount = cs_op_count(handle,insn,ARM_OP_REG);
    if (acount) {
        if(acount<2)
            printf("getSecondReg 少于一个寄存器\n");
        for (i = 1; i < acount + 1;i++) {
            int index = cs_op_index(handle,insn,ARM_OP_REG,i);
            if(i==2){
                s_reg = insn->detail->arm.operands[index].reg;
                return s_reg;
            }
        }
    }
    return 0;
}

//根据寄存器名字得到对应的变量
#pragma mark imp:根据寄存器名字得到对应的变量
uint32_t* getActualVarFromRegName(uint64_t address,int RegName){
    switch (RegName) {
        case ARM_REG_R0:
            return &r0;
            break;
        case ARM_REG_R1:
            return &r1;
            break;
        case ARM_REG_R2:
            return &r2;
            break;
        case ARM_REG_R3:
            return &r3;
            break;
        case ARM_REG_R4:
            return &r4;
            break;
        case ARM_REG_R5:
            return &r5;
            break;
        case ARM_REG_R6:
            return &r6;
            break;
        case ARM_REG_R7:
            return &r7;
            break;
        case ARM_REG_R8:
            return &r8;
            break;
        default:
            break;
    }
    if(printWarnFromRegDidtSet)
        printf("0x%llx getActualVarFromRegName 没有设置对应的寄存器\n",address);
    return NULL;
}


//转换汇编的虚拟内存地址,返回在内存中的实际内容
#pragma mark imp:转换汇编的虚拟内存地址,返回在内存中的实际内容
void* getMemFromAddrOfVM(void* bin,uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr){
    uint64_t offset = cur_VMAddr - CurFunc_VMbaseAddr;
    return bin+CurFunc_FilebaseAddr+offset;
}

//转换虚拟内存地址,返回文件中偏移地址
#pragma mark imp:转换虚拟内存地址,返回文件中偏移地址
uint64_t getfileoffFromAddrOfVM(uint64_t CurFunc_FilebaseAddr,uint64_t CurFunc_VMbaseAddr,uint64_t cur_VMAddr){
    return (uint64_t)((uint64_t)CurFunc_FilebaseAddr+((uint64_t)cur_VMAddr-(uint64_t)CurFunc_VMbaseAddr));
}

//计算返回根据thumb指令pc(+2/4)+offset的地址
#pragma mark imp:计算返回根据thumb指令pc(+2/4)+offset的地址
uint64_t getPCinThumboffset(uint64_t base,int offset){
    uint64_t result = 0;
    if(base%2!=0){
        printf("Memory alignment error\n");
        exit(1);
    }
    if(base%4==0){
        result = base+offset+0x4;
        //printf("---4\n");
    }
    else{
        result = base+offset+0x2;
        //printf("---2\n");
    }
    
    return result;
}

//分析该IO类的函数表等处在_const sec的内容
#pragma mark imp:分析该IO类的函数表等处在_const sec的内容
void ParseConstFunc(char **cn,uint32_t class_self,uint32_t class_super,void *bin,uint64_t VMaddr,uint64_t fileoff){
    
    if(!strcmp(*cn,"")){
        //非所需的str指令
        return;
    }
    else{
        if(!strcmp(*cn,"OSObject"))
            return;
        if(class_self==0){
            printf("class_self 为0\n");
            exit(1);
        }
        
        uint64_t __text_start = machoGetVMAddr(bin,"__TEXT","__text");
        uint64_t __text_end = __text_start + machoGetSize(bin,"__TEXT","__text");
        
        uint64_t __const_start = machoGetVMAddr(bin,"__DATA","__const");
        //uint64_t __const_end = __const_start + machoGetSize(bin,"__TEXT","__const");
        
        uint64_t vtable_start = 0; //为该类的vtable起始位置,可以用来分析重要的函数重写等
        uint64_t vtable_checkItSuperClassAddr = 0; //检查其父类地址
        
        //先找到该IO对象在__const section中的起始地址
        /*格式:
         IO类地址+0x4
         IO父类地址+0x4
         IO类函数表
         */
        for(uint64_t cur_addr = VMaddr;cur_addr>=__const_start;){
            //这里是尝试在内存中找到自己类的地址的匹配
            uint32_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,cur_addr);
            if(!memcmp(check_curAddr,&class_self,0x4)){
                //找到啦~ じゃ保存起来
                vtable_start = cur_addr;
                break;
            }
            cur_addr = cur_addr - 0x4;
        }
        
        if(class_super!=0){
            for(uint64_t cur_addr = VMaddr;cur_addr>=__const_start;){
                //这里是经过IOUserClient后多出的检查,尝试在内存中找到父类地址的匹配,这样的话,通常和上面找到的地址应该相差0x4字节
                uint32_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,cur_addr);
                if(!memcmp(check_curAddr,&class_super,0x4)){
                    //找到,下面进行检查
                    vtable_checkItSuperClassAddr = cur_addr;
                    break;
                }
                cur_addr = cur_addr - 0x4;
            }
        }
        else{
            if(strcmp(*cn,"OSObject")&&strcmp(*cn,"OSMetaClass")){
                //过滤掉OSObject,还有个OSMetaClass同样没有父类
                printf("没有父类\n");
                exit(1);
            }
        }
        
        if(vtable_start==0){
            //没找到的话..ん..丢错
            
            //btw,能到这里的类都是下面的这种格式
            /*格式:
             IO类函数表
             (中间什么都没有,紧接上一个类函数表)
             IO类函数表
             */
            //所以也没有必要确认父类的值,父类的值离这里好远好远
            if(printAddrOfVtable&&printInfoOfKernel){
                printf("name:%s Did't found head of vtable for this IOKit object\n",*cn);
                //exit(1);
                //如果需要停下来看清楚
                //sleep(3);
            }
            
#pragma mark 白名单系统
            if(isInKEXTnow){
                //说明当前在分析内核扩展.如果没找到vtable的话.就得手动分析了...期待看到"- - - END - - -"
                 printf("KEXT name:%s: This class didn't found vtable, so please manual analysis\n",*cn);
                printf("hmm,当然,手动分析后,可以把这个类添加到过滤列表里,下次程序就不会在这里终止了\n");
                //下面是过滤列表
                //按照格式if(strcmp(*cn,"xxx")&&strcmp(*cn,"xxx").....) 的写进去
                if(strcmp(*cn,"com_apple_AppleFSCompression_AppleFSCompressionTypeZlib")){
                    exit(1);
                }
                //- - - 分割线
            }
            
            return;
        }
        
        if(class_super&&vtable_checkItSuperClassAddr){
            if(vtable_start<vtable_checkItSuperClassAddr){
                
                //因此判读父类前4字节是否为自己的地址,不是的话就直接把这个父类的地址当作vtable_start就行了.
                uint32_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_checkItSuperClassAddr-0x4);
                if(check_PointerAddrInVM((uint64_t)check_curAddr)){
                    if(*check_curAddr==class_self){
                        /*正常情况:
                         IO类地址+0x4
                         IO父类地址+0x4
                         IO类函数表
                         */
                        //其实不同的内核好像并不一样,诶,下面多加个检查好了,毕竟相差1字节就是错了
                        //printf("一样\n");
                    }
                    else{
                        /*其他情况:
                         IO父类地址+0x8
                         IO类函数表
                         *///这个就是为IOUserClient准备的
                        vtable_start = vtable_checkItSuperClassAddr;
                    }
                }
                else{
                    printf("0x88这里指针出错\n");
                    exit(1);
                }
                //printf("父类较大\n");
            }
            else if(vtable_start>vtable_checkItSuperClassAddr){
                /*格式:
                 IO类地址+0x8
                 (无父类地址)
                 IO类函数表
                 */
                //printf("自己较大\n");
                //正常的
            }
            else{
                printf("Strange error occur: Should't reach here\n");
                exit(1);
            }
        }
        
        //下面这些判断是根据二段结果,指向对象自己的指针的下方有一段为0的内存,继而找到0内存下面的函数表
        if(vtable_start){
            for(int i=0x0;i<0x28;i=i+0x4){
                uint32_t *check_curAddr = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start+i);
                if(check_PointerAddrInVM((uint64_t)check_curAddr)){
                    if(*check_curAddr==0x0){
                        vtable_start = vtable_start + i;
                        for(int z=0x0;z<0x28;z=z+0x4){
                            uint32_t *check_non_empty = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start+z);
                            if(check_PointerAddrInVM((uint64_t)check_non_empty)){
                                if(*check_non_empty!=0){
                                    vtable_start = vtable_start + z;
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        
        if(printAddrOfVtable&&isInKEXTnow||(!isInKEXTnow&&printInfoOfKernel&&printAddrOfVtable))
            printf("vtable start from addr 0x%llx\n",vtable_start);
        int methods_start = 0;
        
        //待添加代码,上面部分得到了类的函数表.接下来应该获取被重写的函数等信息.
        
        //printf("%s MetaClassvtable:0x%x fileoff:0x%llx\n",*cn,VMaddr,fileoff);
        if(printMCFunc)
            printf("Meta vtable 0x%llx\n",VMaddr); //继承自OSMetaClass的基础函数表地址
        
        /*if(vtable_start&&strstr(*cn,"UserClient")){
         uint32_t *thereis = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x3Bc);
         //if(*thereis!=0xffffff801bf896c4&&*thereis!=0xffffff801bf87e60)
         printf("thereis is 0x%x from:0x%llx\n",*thereis,vtable_start + 0x3Bc);
         }*/
        
        //下面判断类名,来得到基础类的函数信息赋值给全局变量,当失败的时候程序自然会终止.但这种可能性很小,经过前面的检查,这里出错的几率非常小
        if(!strcmp(*cn,"IOService")){
            IOService_newUserClientWithOSDic = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x244);
            //IOService::newUserClient(task *,void *,ulong,OSDictionary *,IOUserClient **)
            
            IOService_newUserClient = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x248);
            //IOService::newUserClient(task *,void *,ulong,IOUserClient **)
            
            
            if(*IOService_newUserClientWithOSDic>__text_start) {
                if(printFuncFinderOfKernel)
                    printf("IOService::newUserClientWithOSDic -> 0x%x -1\n",*IOService_newUserClientWithOSDic);
            }
            else{
                printf("%s处地址错误\n",*cn);
                exit(1);
            }
            
            if(*IOService_newUserClient>__text_start) {
                if(printFuncFinderOfKernel)
                    printf("IOService::newUserClient -> 0x%x -1\n",*IOService_newUserClient);
            }
            else{
                printf("%s处地址错误\n",*cn);
                exit(1);
            }
        }
        
        if(!strcmp(*cn,"IOUserClient")){
            IOUserClient_externalMethod = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x340);
            IOUserClient_clientMemoryForType = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x368);
            IOUserClient_getExternalMethodForIndex = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x374);
            IOUserClient_getTargetAndMethodForIndex = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x37C);
            IOUserClient_getExternalTrapForIndex = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x384);
            IOUserClient_getTargetAndTrapForIndex = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x388);
            if(*IOUserClient_externalMethod>__text_start) {
                if(printFuncFinderOfKernel)
                    printf("IOUserClient::externalMethod -> 0x%x -1\n",*IOUserClient_externalMethod);
            }
            else{
                printf("%s处地址错误\n",*cn);
                exit(1);
            }
            if(*IOUserClient_clientMemoryForType>__text_start) {
                if(printFuncFinderOfKernel)
                    printf("IOUserClient::clientMemoryForType -> 0x%x -1\n",*IOUserClient_clientMemoryForType);
            }
            else{
                printf("%s处地址错误\n",*cn);
                exit(1);
            }
            if(*IOUserClient_getExternalMethodForIndex>__text_start) {
                if(printFuncFinderOfKernel)
                    printf("IOUserClient::getExternalMethodForIndex -> 0x%x -1\n",*IOUserClient_getExternalMethodForIndex);
            }
            else{
                printf("%s处地址错误\n",*cn);
                exit(1);
            }
            if(*IOUserClient_getTargetAndMethodForIndex>__text_start) {
                if(printFuncFinderOfKernel)
                    printf("IOUserClient::getTargetAndMethodForIndex -> 0x%x -1\n",*IOUserClient_getTargetAndMethodForIndex);
            }
            else{
                printf("%s处地址错误\n",*cn);
                exit(1);
            }
            if(*IOUserClient_getExternalTrapForIndex>__text_start) {
                if(printFuncFinderOfKernel)
                    printf("IOUserClient::getExternalTrapForIndex -> 0x%x -1\n",*IOUserClient_getExternalTrapForIndex);
            }
            else{
                printf("%s处地址错误\n",*cn);
                exit(1);
            }
            if(*IOUserClient_getTargetAndTrapForIndex>__text_start) {
                if(printFuncFinderOfKernel)
                    printf("IOUserClient::getTargetAndTrapForIndex -> 0x%x -1\n",*IOUserClient_getTargetAndTrapForIndex);
            }
            else{
                printf("%s处地址错误\n",*cn);
                exit(1);
            }
        }
        // - - -分割线
        
        int frIOUserClient = 0; //继承自xxx
        int frIOService = 0; //上も
        
        if(isInKEXTnow){
            //关于vtable之前已经判断过了,所以这里就不做检查了.
            //前面获得了一个类的两个值可以确定函数表范围 vtable开始 - metaclass函数开始
            //根据父类继承来得到是否继承自IOService或者IOUserClient
            //再分析重要的重写函数
            printf("Inheritance relationship: ");
            NSString *cur_c = [NSString stringWithFormat:@"0x%x",class_super];
            while(1){
                NSDictionary *s_dic = [allClass_relation objectForKey:cur_c];
                if(s_dic){
                    if(![cur_c isEqualToString:[NSString stringWithFormat:@"0x%x",class_super]])
                        printf("->");
                    NSString *s_class = [NSString stringWithFormat:@"0x%x",[[s_dic objectForKey:@"class_super"] intValue]];
                    NSString *s_classN = [s_dic objectForKey:@"class_name"];
                    if([s_classN isEqualToString:@"IOUserClient"])
                        frIOUserClient = 1;
                    if([s_classN isEqualToString:@"IOService"])
                        frIOService = 1;
                    
                    printf("%s",[s_classN cStringUsingEncoding:NSUTF8StringEncoding]);
                    cur_c = s_class;
                }
                else{
                    break;
                }
            }
            printf("\n");
        }
        else{
            //if(!vtable_start)
            //这里说明当前在分析内核的对象,那么无须分析重写的函数,因为内核的对象都是些基础类,况且前面已经判断过了.
        }
        
#pragma mark part:对重写的函数进行过滤
        /*if(vtable_start&&strstr(*cn,"UserClient")){
         uint32_t *thereis = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x3B4);
         //if(*thereis!=0xffffff801bf896c4&&*thereis!=0xffffff801bf87e60&&*thereis!=0xffffff801bf88688&&*thereis!=0xffffff801bf88690)
         printf("thereis is 0x%x from:0x%llx\n",*thereis,vtable_start + 0x3B4);
         }*/
        
        
#pragma mark edit:判断类重写的函数
        //判断重写的函数
        
        if(frIOUserClient){
            //list:
            //IOUserClient::externalMethod
            uint32_t *own_externalMethod = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x340);
            uint32_t *own_clientMemoryForType = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x368);
            uint32_t *own_getExternalMethodForIndex = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x374);
            uint32_t *own_getTargetAndMethodForIndex = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x37C);
            uint32_t *own_getExternalTrapForIndex = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x384);
            uint32_t *own_getTargetAndTrapForIndex = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x388);
            if(*own_externalMethod!=*IOUserClient_externalMethod){
                printf("override: externalMethod loc:0x%llx imp:0x%x\n",vtable_start + 0x340,*own_externalMethod);
            }
            if(*own_clientMemoryForType!=*IOUserClient_externalMethod){
                printf("override: clientMemoryForType loc:0x%llx imp:0x%x\n",vtable_start + 0x368,*own_clientMemoryForType);
            }
            if(*own_getExternalMethodForIndex!=*IOUserClient_getExternalMethodForIndex){
                printf("override: getExternalMethodForIndex loc:0x%llx imp:0x%x\n",vtable_start + 0x374,*own_getExternalMethodForIndex);
            }
            if(*own_getTargetAndMethodForIndex!=*IOUserClient_getTargetAndMethodForIndex){
                printf("override: getTargetAndMethodForIndex loc:0x%llx imp:0x%x\n",vtable_start + 0x37C,*own_getTargetAndMethodForIndex);
            }
            if(*own_getExternalTrapForIndex!=*IOUserClient_getExternalTrapForIndex){
                printf("override: getExternalTrapForIndex loc:0x%llx imp:0x%x\n",vtable_start + 0x384,*own_getExternalTrapForIndex);
            }
            if(*own_getTargetAndTrapForIndex!=*IOUserClient_getTargetAndTrapForIndex){
                printf("override: getTargetAndTrapForIndex loc:0x%llx imp:0x%x\n",vtable_start + 0x388,*own_getTargetAndTrapForIndex);
            }
            //printf("\nown_externalMethod: 0x%x\n",*own_externalMethod);
        }
        
        if(frIOService){
            //list:
            //IOService::newUserClientWithOSDic; //IOService + 0x244
            //IOService::newUserClient; //IOService + 0x248
            uint32_t *own_newUserClientWithOSDic = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x244);
            uint32_t *own_newUserClient = getMemFromAddrOfVM(bin,fileoff,VMaddr,vtable_start + 0x248);
            if(*own_newUserClientWithOSDic!=*IOService_newUserClientWithOSDic){
                printf("override: newUserClientWithOSDic loc:0x%llx imp:0x%x\n",vtable_start + 0x244,*own_newUserClientWithOSDic);
                //下面是输出文件
                [class_newUserClientWithOSDic addObject:[NSString stringWithFormat:@"%s",*cn]];
            }
            if(*own_newUserClient!=*IOService_newUserClient){
                printf("override: newUserClient loc:0x%llx imp:0x%x\n",vtable_start + 0x248,*own_newUserClient);
                //下面是输出文件
                [class_newUserClient addObject:[NSString stringWithFormat:@"%s",*cn]];
            }
            //printf("\nown_externalMethod: 0x%x\n",*own_externalMethod);
        }
        
        printf("\n");
        if(isUserClient==1||frIOUserClient){
            //为UserClinet类分析methods
            //selector 0
            uint32_t *check_func_0 = 0;
            uint32_t *check_scalar_i_0 = 0;
            uint32_t *check_struct_i_0 = 0;
            uint32_t *check_scalar_o_0 = 0;
            uint32_t *check_struct_o_0 = 0;
            
            int vm_i = 0;
            
            for(vm_i = 0;vm_i<0x50;vm_i++){
                check_func_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4);
                check_scalar_i_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4+4);
                check_struct_i_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4+8);
                check_scalar_o_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4+12);
                check_struct_o_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4+16);
                
                if(
                   ((*check_func_0 > __text_start)&&(*check_func_0 < __text_end))&&(*check_scalar_i_0 < 0xffff||*check_scalar_i_0 == 0xffffffff)&&(*check_struct_i_0 < 0xffff || *check_struct_i_0 == 0xffffffff)&&(*check_scalar_o_0 < 0xffff || *check_scalar_o_0 == 0xffffffff) && (*check_scalar_i_0 < 0xffff || *check_scalar_i_0 == 0xffffffff))
                {
                    //找到开头
                    methods_start = (uint32_t)VMaddr+vm_i*4;
                    if(methods_start==0){
                        printf("methods_start 为0错误\n");
                        exit(1);
                    }
                    if(printAddrOfMethod)
                        printf("%s methods table in 0x%x\n",*cn,methods_start);
                    break;
                }
            }
            
            if(methods_start!=0){
                NSMutableArray *methods_array = [[NSMutableArray alloc]init];
                for(int mi = 0;;){
                    check_func_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4);
                    check_scalar_i_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4+4);
                    check_struct_i_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4+8);
                    check_scalar_o_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4+12);
                    check_struct_o_0  = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+vm_i*4+16);
                    if(
                       ((*check_func_0 > __text_start)&&(*check_func_0 < __text_end))&&(*check_scalar_i_0 < 0xffff||*check_scalar_i_0 == 0xffffffff)&&(*check_struct_i_0 < 0xffff || *check_struct_i_0 == 0xffffffff)&&(*check_scalar_o_0 < 0xffff || *check_scalar_o_0 == 0xffffffff) && (*check_scalar_i_0 < 0xffff || *check_scalar_i_0 == 0xffffffff))
                    {
                        NSMutableDictionary *methods_each_detail_dic = [[NSMutableDictionary alloc]init];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_func_0] forKey:@"func"];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_scalar_i_0] forKey:@"scalar_i"];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_struct_i_0] forKey:@"struct_i"];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_scalar_o_0] forKey:@"scalar_o"];
                        [methods_each_detail_dic setObject:[NSNumber numberWithUnsignedInt:*check_struct_o_0] forKey:@"struct_o"];
                        [methods_array addObject:methods_each_detail_dic];
                        if(printMethodsInfo){
                            printf("%d func:0x%x  scalar_i:0x%x  struct_i:0x%x  scalar_o:0x%x  struct_o:0x%x\n",mi,*check_func_0,*check_scalar_i_0,*check_struct_i_0,*check_scalar_o_0,*check_struct_o_0);
                        }
                        mi++;
                    }
                    else{
                        break;
                    }
                    vm_i = vm_i + 5;
                }
                if([methods_array count]>0){
                    [class_userCleint_methods setObject:methods_array forKey:[NSString stringWithFormat:@"%s",*cn]];
                }
            }
        }
        /*int i,allocM;
         for(i=0;i<20;i++){
         uint32_t *tar_addr = getMemFromAddrOfVM(bin,fileoff,VMaddr,VMaddr+i*4);
         if(*tar_addr==0){
         break;
         }
         if(i>12){
         printf("0x%llx findAllocFunc有超出13个OSMetaClass函数\n",VMaddr);
         exit(1);
         }
         
         if(i==12){
         //printf("%s allocFunc -> 0x%x\n\n",*cn,(*tar_addr)-1);
         allocM = (*tar_addr)-1;
         }
         //printf("%d.0x%x\n",i,*tar_addr);
         }*/ //找到该IO重写的alloc函数
    }
    *cn = "";
    class_self = 0;
    class_super = 0;
}

//检查指针指向位置是否在已分配的虚拟内存内,正确返回1
#pragma mark imp:检查指针指向位置是否在已分配的虚拟内存内,正确返回1
int check_PointerAddrInVM(uint64_t tar_addr)
{
    //仅限使用64位程序,32位请修改
    int pid = 0;
    pid_for_task(mach_task_self(),&pid);
    
    vm_map_t task = 0;
    task_for_pid(mach_task_self(),pid,&task);
    
    int avai = 0;
    
    kern_return_t ret;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0;
    while (1) {
        ret = vm_region_recurse_64(task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);
        
        if (ret != KERN_SUCCESS)
            break;
        if(addr>0x7fff00000000)
            break;
        if(tar_addr>=addr&&tar_addr<=addr+size){
            avai = 1;
        }
        //printf("region 0x%lx - 0x%lx\n",addr,addr+size);
        addr = addr + size;
    }
    
    if(avai==1)
        return 1;
    else
        return 0;
    
    return 0;
}

