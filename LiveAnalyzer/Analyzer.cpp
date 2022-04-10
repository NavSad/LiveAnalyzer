//
//  Analyzer.cpp
//  LiveAnalyzer
//
//  Created by NavSad on 6/1/20.
//  Copyright © 2020 NavSad. All rights reserved.
//

#include "Analyzer.hpp"



void Analyzer()
{
    FindBase();
    //Add function to find kernel base
    std::string Input;
    std::vector<std::string> Inputs;
    while(true)
    {
        std::cout<<"Analyzer> ";
        int input=check_for_chars();
        getline(std::cin,Input);
        //std::cout<<getchar()<<"\n";
        //char ch=getchar();
        Inputs.push_back(Input);
        if(strncmp(Input.c_str(), "help", 4)==0 || strncmp(Input.c_str(), "-h", 2)==0)
        {
            std::cout<<"rkern <address> <length> (Reads from the live kernel in memory at a certain address for a specified length.)"<<"\n";
            std::cout<<"wkern <address> <data> <length> (Writes data to the live kernel in memory at a certain address for a specified length.)"<<"\n";
            std::cout<<"attach <pid> (Attatches to a pid, which allows for debugging.)"<<"\n";
            std::cout<<"base (Prints kernel base in memory along with the slide.)"<<"\n";
            std::cout<<"exit (Exits.)"<<"\n";
            //Add more commands
            continue;
        }
        
        if(strncmp(Input.c_str(), "rkern", 5)==0)
        {
            //std::cout<<"Made it here."<<"\n";
            std::size_t found=Input.find_first_of(" ");
            std::size_t found_1;
            while(found!=std::string::npos)
            {
                found_1=found;
                found=Input.find_first_of(" ",found+1);
                std::string Address=Input.substr(found_1,found-found_1);
                found_1=found;
                found=Input.find_first_of(" ",found+1);
                std::string Size=Input.substr(found_1,found-found_1);
                std::cout<<Address<<"\n";
                std::cout<<Size<<"\n";
            }
        }
        
        if(strncmp(Input.c_str(),"attach", 6)==0)
        {
            std::size_t found=Input.find_first_of(" ");
            std::string Pid=Input.substr(found);
            pid_t pid=std::stoi(Pid);
            if(pid==0)
            {
                std::cout<<"Please use the kernel analyzer."<<"\n";
                continue;
            }
            if(getpid()==pid)
            {
                std::cerr<<"We cannot analyzer ourselves."<<"\n";
                continue;
            }
            std::cout<<"Searching for pid "<<pid<<"."<<"\n";
            int proc_num=proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
            pid_t pids[proc_num];
            bzero(pids,sizeof(pids));
            proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
            for(int i=0;i<proc_num;i++)
            {
                if(pids[i]==pid || pids[i]!=pid)
                {
                    if(pids[i]==pid)
                    {
                        std::cout<<"Found pid "<<pid<<"."<<"\n";
                        Attach(pid);
                        break;
                    }
                    if(pids[i]!=pid)
                    {
                        if(i==proc_num-1)
                        {
                            std::cerr<<"Did not find pid "<<pid<<"."<<"\n";
                            break;
                        }
                        continue;
                    }
                }
            }
            continue;
        }
        
        if(strncmp(Input.c_str(), "base", 4)==0)
        {
            //Add the base functions
        }
        
        if(strncmp(Input.c_str(), "exit", 4)==0)
        {
            //Do any cleanup operation if necessary
            break;
        }
        if(input==1<<2)
        {
            std::cout<<"Made it here."<<"\n";
            continue;
        }
        if(input==1<<1)
        {
            
        }
        else
        {
            std::cout<<"Invalid command. Please use 'help' or '-h' to see a list of commands."<<"\n";
            continue;
        }
    }
    
}

uint64_t FindBase()
{
    host_t host=mach_host_self();
    mach_port_t ps_default;
    mach_port_t ps_default_control;
    task_array_t tasks;
    mach_msg_type_number_t num_tasks;
    int t;
    kern_return_t kr;
    mach_port_t kern_port;
    if(is_set(TARGET_OS_IOS))
    {
        kr=task_for_pid(mach_task_self(), 0, &kern_port);
        if(kr!=KERN_SUCCESS)
        {
            kr=host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kern_port);
            if(kr!=KERN_SUCCESS)
            {
                std::cerr<<"Failed to get the kernel task port."<<"\n";
                exit(1);
            }
        }
    }
    if(is_set(TARGET_OS_OSX))
    {
        kr=processor_set_default(host, &ps_default);
        kr=host_processor_set_priv(host, ps_default, &ps_default_control);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to set host processor privilleges."<<"\n";
            exit(1);
        }
        kr=processor_set_tasks(ps_default_control,&tasks,&num_tasks);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to set processor tasks."<<"\n";
            exit(1);
        }
        for(t=0;t<num_tasks;t++)
        {
            int pid;
            pid_for_task(tasks[t],&pid);
            std::cout<<"Task: "<<tasks[t]<<" pid: "<<pid<<"\n";
            if(pid==0)
            {
                kern_port=tasks[t];
                break;
            }
        }
        /*kern_return_t kr=task_for_pid(mach_task_self(), 0, &kern_port);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to get kernel task port."<<"\n";
            exit(1);
        }
         */
    }
    mach_vm_address_t address=0;
    for(;;)
    {
        mach_vm_size_t size=0;
        uint32_t depth=2;
        vm_region_submap_info_64 info;
        mach_msg_type_number_t count=VM_REGION_SUBMAP_INFO_COUNT_64;
        kr=mach_vm_region_recurse(kern_port, &address, &size, &depth, (vm_region_recurse_info_t)&info, &count);
        if(kr!=KERN_SUCCESS)
        {
            break;
        }
        
    }
    
    /*uint64_t base_addr=0xffffff8000100000;
    vm_offset_t data;
    mach_msg_type_number_t data_count;
    uint64_t kernel_slide;
    uint64_t current_slide;
    for(int slide_byte=256;slide_byte>=1;slide_byte--)
    {
        kernel_slide = 0x01000000 + 0x00200000 * slide_byte;
        current_slide=base_addr+kernel_slide;
        kr=vm_read(kern_port, current_slide, 8, &data, &data_count);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to read kernel memory."<<"\n";
            exit(1);
        }
     
     
    
    }*/
    //std::cout<<data<<"\n";
    //std::cout<<data_count<<"\n";
    return 0;
}

void Attach(pid_t pid)
{
    kern_return_t kr;
    mach_port_name_t task_port;
    mach_port_name_t exception_port;
    task_for_pid(mach_task_self(), pid, &task_port);
    exception_mask_t saved_masks[EXC_TYPES_COUNT];
    mach_port_t saved_ports[EXC_TYPES_COUNT];
    exception_behavior_t saved_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t saved_flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t saved_exception_types_count;
    task_get_exception_ports(task_port, EXC_MASK_ALL, saved_masks, &saved_exception_types_count, saved_ports, saved_behaviors, saved_flavors);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
    mach_port_insert_right(mach_task_self(),exception_port,exception_port,MACH_MSG_TYPE_MAKE_SEND);
    task_set_exception_ports(task_port, EXC_MASK_ALL, exception_port, EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
    ptrace(PT_ATTACHEXC,pid,0,0);
    //ptrace(PT_THUPDATE,pid,0,0);
    std::string Input;
    while(true)
    {
        std::cout<<"Attach> ";
        getline(std::cin,Input);
        if(strncmp(Input.c_str(), "help", 4)==0 || strncmp(Input.c_str(), "-h", 2)==0)
        {
            std::cout<<"base (Prints the base address of the process.)"<<"\n";
            std::cout<<"suspend (Suspends the running process.)"<<"\n";
            std::cout<<"resume (Resumes the suspended process.)"<<"\n";
            std::cout<<"rreg (Read the processes's registers.)"<<"\n";
            std::cout<<"wreg <register> <value> (Writes the value to the specified register.)"<<"\n";
            std::cout<<"rmem <address> <size> (Reads the processes's memory starting from the specified address. If address is 0, it will start reading from the base address of the process.)"<<"\n";
            std::cout<<"wmem <address> <value> <size> (Writes the specified value to the processes's memory starting at the specified address. If address is 0, it will start writing from the base address of the process.)"<<"\n";
            std::cout<<"return (Returns to the main screen.)"<<"\n";
            continue;
            //Add more
        }
        if(strncmp(Input.c_str(),"base",4)==0)
        {
            FindBase(task_port,pid);
            continue;
        }
        if(strncmp(Input.c_str(), "rreg", 4)==0)
        {
            rreg(task_port);
            continue;
        }
        if(strncmp(Input.c_str(),"wreg", 4)==0)
        {
            try
            {
                std::size_t found=Input.find_first_of(" ");
                std::size_t found1=Input.find_last_of(" ");
                std::string registers=Input.substr(found,found1-found);
                found=Input.find_first_of(" ",found+1);
                std::string Value=Input.substr(found);
                uint64_t value=std::stoi(Value);
                registers.erase(remove_if(registers.begin(),registers.end(),isspace),registers.end());
                wreg(task_port, registers, value);
                continue;
            }
            catch (std::exception& x)
            {
                std::cerr<<"Invalid syntax."<<"\n";
                continue;
            }
        }
        if(strncmp(Input.c_str(),"rmem", 4)==0)
        {
            try
            {
                std::size_t found=Input.find_first_of(" ");
                std::size_t found1=Input.find_last_of(" ");
                std::string Address=Input.substr(found,found1-found);
                found=Input.find_first_of(" ",found+1);
                std::string Size=Input.substr(found);
                uint64_t address=std::stoi(Address);
                uint64_t size=std::stoi(Size);
                rmem(task_port,address,size);
                continue;
            }
            catch (std::exception& x)
            {
                std::cerr<<"Invalid syntax."<<"\n";
                continue;
            }
        }
        if(strncmp(Input.c_str(),"wmem", 4)==0)
        {
            try
            {
                 std::size_t found=Input.find_first_of(" ");
                 std::size_t found1=Input.find_last_of(" ");
                 found1=Input.find_last_of(" ",found1-1);
                 std::string Address=Input.substr(found,found1-found);
                 found=Input.find_first_of(" ",found+1);
                 found1=Input.find_last_of(" ");
                 std::string Data=Input.substr(found,found1-found);
                 found=Input.find_first_of(" ",found+1);
                 std::string Size=Input.substr(found);
                 //std::cout<<Address<<"\n";
                 //std::cout<<Data<<"\n";
                 //std::cout<<Size<<"\n";
                 uint64_t address=std::stoi(Address);
                 size_t size=std::stoi(Size);
                 wmem(task_port,address,Data,size);
                 continue;
            }
            catch (std::exception& x)
            {
                std::cerr<<"Invalid syntax."<<"\n";
                continue;
            }
        }
        if(strncmp(Input.c_str(), "suspend", 7)==0)
        {
            kr=task_suspend(task_port);
            if(kr!=KERN_SUCCESS)
            {
                std::cerr<<"Failed suspending the process."<<"\n";
            }
            continue;
        }
        if(strncmp(Input.c_str(), "return", 6)==0)
        {
            //Fix
            for(int i=0;i<saved_exception_types_count;i++)
            {
                task_set_exception_ports(task_port, saved_masks[i], saved_ports[i], saved_behaviors[i], saved_flavors[i]);
            }
            ptrace(PT_DETACH,pid,0,0);
            mach_port_deallocate(mach_task_self(), exception_port);
            if(!ptrace(PT_DETACH,pid,0,0))
            {
                kill(pid,SIGKILL);
            }
            return;
        }
        if(strncmp(Input.c_str(), "resume", 6)==0)
        {
            kr=task_resume(task_port);
            if(kr!=KERN_SUCCESS)
            {
                std::cerr<<"Failed resuming the process."<<"\n";
            }
            continue;
        }
        else
        {
            std::cout<<"Invalid command. Please use 'help' or '-h' to see a list of commands."<<"\n";
            continue;
        }
    }
}

void FindBase(mach_port_name_t task_port,pid_t pid)
{
    kern_return_t kr;
    vm_map_offset_t vmoffset=0;
    vm_map_size_t vmsize;
    uint32_t nesting_depth=0;
    vm_region_submap_info_64 vbr;
    mach_msg_type_number_t vbrcount=16;
    kr=mach_vm_region_recurse(task_port, &vmoffset, &vmsize, &nesting_depth, (vm_region_recurse_info_t)&vbr, &vbrcount);
    if(kr!=KERN_SUCCESS)
    {
        std::cerr<<"Failed to get process base address."<<"\n";
        return;
    }
    std::cout<<"pid: "<<pid<<"\n";
    std::cout<<"Base Address: "<<std::hex<<"0x"<<vmoffset<<"\n";
    std::cout<<"Task port: "<<std::hex<<"0x"<<task_port<<"\n";
    return;
}

void rreg(mach_port_name_t task_port)
{
    if(is_set(TARGET_CPU_X86_64))
    {
         thread_act_port_array_t thread_list;
         mach_msg_type_number_t thread_count;
         task_threads(task_port, &thread_list, &thread_count);
         x86_thread_state_t x86_state;
         mach_msg_type_number_t state_count=x86_THREAD_STATE_COUNT;
         long thread=0;
         thread_get_state(thread_list[thread],x86_THREAD_STATE,(thread_state_t)&x86_state,&state_count);
         std::cout<<"rax: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rax<<"\n";
         std::cout<<"rbx: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rbx<<"\n";
         std::cout<<"rcx: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rcx<<"\n";
         std::cout<<"rdx: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rdx<<"\n";
         std::cout<<"rdi: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rdi<<"\n";
         std::cout<<"rsi: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rsi<<"\n";
         std::cout<<"rbp: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rbp<<"\n";
         std::cout<<"rsp: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rsp<<"\n";
         std::cout<<"r8: "<<std::hex<<"0x"<<x86_state.uts.ts64.__r8<<"\n";
         std::cout<<"r9: "<<std::hex<<"0x"<<x86_state.uts.ts64.__r9<<"\n";
         std::cout<<"r10: "<<std::hex<<"0x"<<x86_state.uts.ts64.__r10<<"\n";
         std::cout<<"r11: "<<std::hex<<"0x"<<x86_state.uts.ts64.__r11<<"\n";
         std::cout<<"r12: "<<std::hex<<"0x"<<x86_state.uts.ts64.__r12<<"\n";
         std::cout<<"r13: "<<std::hex<<"0x"<<x86_state.uts.ts64.__r13<<"\n";
         std::cout<<"r14: "<<std::hex<<"0x"<<x86_state.uts.ts64.__r14<<"\n";
         std::cout<<"r15: "<<std::hex<<"0x"<<x86_state.uts.ts64.__r15<<"\n";
         std::cout<<"rip: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rip<<"\n";
         std::cout<<"rflags: "<<std::hex<<"0x"<<x86_state.uts.ts64.__rflags<<"\n";
         std::cout<<"cs: "<<std::hex<<"0x"<<x86_state.uts.ts64.__cs<<"\n";
         std::cout<<"fs: "<<std::hex<<"0x"<<x86_state.uts.ts64.__fs<<"\n";
         std::cout<<"gs: "<<std::hex<<"0x"<<x86_state.uts.ts64.__gs<<"\n";
         //Add more registers
    }
   if(is_set(TARGET_CPU_ARM64))
   {
       
       if(is_set(TARGET_OS_OSX))
       {
           //Will add support once Xcode 12 is released
           
       }
   }
   return;
}

void wreg(mach_port_name_t task_port,std::string registers,uint64_t value)
{
      if(is_set(TARGET_CPU_X86_64))
      {
             thread_act_port_array_t thread_list;
             mach_msg_type_number_t thread_count;
             task_threads(task_port, &thread_list, &thread_count);
             x86_thread_state_t x86_state;
             mach_msg_type_number_t state_count=x86_THREAD_STATE_COUNT;
             long thread=0;
             thread_get_state(thread_list[thread],x86_THREAD_STATE,(thread_state_t)&x86_state,&state_count);
             //task_suspend(task_port);
             //std::cout<<registers<<"\n";
             if(registers=="rax")
             {
                 x86_state.uts.ts64.__rax=value;
             }
             else if(registers=="rcx")
             {
                 x86_state.uts.ts64.__rcx=value;
             }
             else if(registers=="rdx")
             {
                 x86_state.uts.ts64.__rdx=value;
             }
             else if(registers=="rbx")
             {
                 x86_state.uts.ts64.__rbx=value;
             }
             else if(registers=="rsi")
             {
                 x86_state.uts.ts64.__rsi=value;
             }
             else if(registers=="rdi")
             {
                 x86_state.uts.ts64.__rdi=value;
             }
             else if(registers=="rsp")
             {
                 x86_state.uts.ts64.__rsp=value;
             }
             else if(registers=="rbp")
             {
                 x86_state.uts.ts64.__rbp=value;
             }
             else if(registers=="r8")
             {
                 x86_state.uts.ts64.__r8=value;
             }
             else if(registers=="r9")
             {
                 x86_state.uts.ts64.__r9=value;
             }
             else if(registers=="r10")
             {
                 x86_state.uts.ts64.__r10=value;
             }
             else if(registers=="r11")
             {
                 x86_state.uts.ts64.__r11=value;
             }
             else if(registers=="r12")
             {
                 x86_state.uts.ts64.__r12=value;
             }
             else if(registers=="r13")
             {
                 x86_state.uts.ts64.__r13=value;
             }
             else if(registers=="r14")
             {
                 x86_state.uts.ts64.__r14=value;
             }
             else if(registers=="r15")
             {
                 x86_state.uts.ts64.__r15=value;
             }
             else if(registers=="rip")
             {
                 x86_state.uts.ts64.__rip=value;
             }
             else if(registers=="rflags")
             {
                 x86_state.uts.ts64.__rflags=value;
             }
             else if(registers=="cs")
             {
                 x86_state.uts.ts64.__cs=value;
             }
             else if(registers=="fs")
             {
                 x86_state.uts.ts64.__fs=value;
             }
             else if(registers=="gs")
             {
                 x86_state.uts.ts64.__gs=value;
             }
             //Add more registers
             else
             {
                 std::cerr<<"Not a valid register."<<"\n";
                 return;
             }
             thread_set_state(thread_list[thread],x86_THREAD_STATE,(thread_state_t)&x86_state,state_count);
             //task_resume(task_port);
      }
    if(is_set(TARGET_CPU_ARM64))
    {
        if(is_set(TARGET_OS_OSX))
        {
            //Will add support after Xcode 12 is released
        }
    }
     
    return;
}

void rmem(mach_port_name_t task_port,uint64_t address,uint64_t size)
{
    kern_return_t kr;
    vm_map_offset_t vmoffset=0;
    vm_map_size_t vmsize;
    uint32_t nesting_depth=0;
    vm_region_submap_info_64 vbr;
    mach_msg_type_number_t vbrcount=16;
    kr=mach_vm_region_recurse(task_port, &vmoffset, &vmsize, &nesting_depth, (vm_region_recurse_info_t)&vbr, &vbrcount);
    pointer_t data;
    mach_msg_type_number_t data_cnt;
    //int page_sz=getpagesize();
    if(address==0)
    {
        address=vmoffset;
        kr=mach_vm_read(task_port, address, size, &data, &data_cnt);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to read process memory."<<"\n";
            return;
        }
        //std::cout<<data_cnt<<"\n";
        unsigned char buffer[data_cnt];
        memcpy(buffer, (const void* )data, data_cnt);
        for(int i=0;i<data_cnt;i++)
        {
            if(i==0)
            {
                std::cout<<"Address    Data"<<"\n";
            }
            std::cout<<std::hex<<"0x"<<address<<" "<<std::hex<<buffer[i]<<"\n";
            address++;
        }
        kr=mach_vm_deallocate(task_port, data, data_cnt);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to deallocate memory."<<"\n";
            return;
        }
    }
    else
    {
        kr=mach_vm_read(task_port, address, size, &data, &data_cnt);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to read process memory."<<"\n";
            return;
        }
        unsigned char buffer[data_cnt];
        memcpy(buffer,(const void *)data,data_cnt);
        for(int i=0;i<data_cnt;i++)
        {
            if(i==0)
            {
                std::cout<<"Address    Data"<<"\n";
            }
            std::cout<<std::hex<<"0x"<<address<<" "<<std::hex<<buffer[i]<<"\n";
            address++;
        }
        kr=mach_vm_deallocate(task_port, data, data_cnt);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to deallocate memory."<<"\n";
            return;
        }
    }
    return;
}

void wmem(mach_port_name_t task_port,uint64_t address,std::string Data,size_t size)
{
    kern_return_t kr;
    vm_map_offset_t vmoffset=0;
    vm_map_size_t vmsize;
    uint32_t nesting_depth=0;
    vm_region_submap_info_64 vbr;
    mach_msg_type_number_t vbrcount=16;
    kr=mach_vm_region_recurse(task_port, &vmoffset, &vmsize, &nesting_depth, (vm_region_recurse_info_t)&vbr, &vbrcount);
    if(address==0)
    {
        address=vmoffset;
        kr=mach_vm_protect(task_port,address, size, false, VM_PROT_WRITE|VM_PROT_READ);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to change the processes's protections."<<"\n";
            return;
        }
        kr=mach_vm_write(task_port, address, (vm_address_t)Data.c_str(), size);
        if(kr!=KERN_SUCCESS)
        {
            std::cerr<<"Failed to write to process memory."<<"\n";
            return;
        }
    }
    kr=mach_vm_protect(task_port, address, size, false, VM_PROT_WRITE|VM_PROT_READ);
    if(kr!=KERN_SUCCESS)
    {
        std::cerr<<"Failed to change the processes's protections."<<"\n";
        return;
    }
    kr=mach_vm_write(task_port, address, (vm_address_t)Data.c_str(), size);
    if(kr!=KERN_SUCCESS)
    {
        std::cerr<<"Failed to write to process memory."<<"\n";
        return;
    }
    return;
}

void wait_for_exception(mach_port_name_t exception_port,mach_port_name_t task_port)
{
    char req[128];
    char rpl[128];
    mach_msg((mach_msg_header_t *)req,MACH_RCV_MSG,0,sizeof(req),exception_port,MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL);
    task_suspend(task_port);
}

int check_for_chars()
{
    filter();
    initscr();
    cbreak();
    noecho();
    keypad(stdscr,TRUE);
    int ch;
    int input=1;
    ch=getch();
    switch (ch)
    {
        case KEY_UP:
            input=input<<2;
            endwin();
            return input;
        case KEY_DOWN:
            input=input<<1;
            endwin();
            return input;
        default:
            endwin();
            return input;
    }
}
