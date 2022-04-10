//
//  Analyzer.hpp
//  LiveAnalyzer
//
//  Created by NavSad on 6/1/20.
//  Copyright © 2020 NavSad. All rights reserved.
//

#ifndef Analyzer_hpp
#define Analyzer_hpp

#include <iostream>
#include <vector>
#include <exception>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/syscall.h>
#include <curses.h>
#include <TargetConditionals.h>


#define is_set(macro) is_set_(macro)
#define macrotest_1 ,
#define is_set_(value) is_set__(macrotest_##value)
#define is_set__(comma) is_set___(comma 1, 0)
#define is_set___(_, v, ...) v

#define UP_ARROW 27

#define DOWN_ARROW 80

void Analyzer();

uint64_t FindBase();

void Attach(pid_t pid);

void rreg(mach_port_name_t task_port);

void wreg(mach_port_name_t task_port,std::string registers,uint64_t value);

void rmem(mach_port_name_t task_port,uint64_t address,uint64_t size);

void FindBase(mach_port_name_t task_port,pid_t pid);

void wmem(mach_port_name_t task_port,uint64_t address,std::string value,size_t size);

void wait_for_exception(mach_port_name_t exception_port,mach_port_name_t task_port);

int check_for_chars();

#endif /* Analyzer_hpp */
