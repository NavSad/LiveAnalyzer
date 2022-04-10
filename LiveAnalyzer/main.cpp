//
//  main.cpp
//  LiveAnalyzer
//
//  Created by NavSad on 6/1/20.
//  Copyright © 2020 NavSad. All rights reserved.
//

#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include "Analyzer.hpp"

using namespace std;

bool is_sip_enabled();

int main()
{
    if(getuid()!=0)
    {
        cerr<<"You must be root to run this."<<"\n";
        return 1;
    }
    bool sip_status=is_sip_enabled();
    if(sip_status==true)
    {
        cout<<"SIP has to be disabled to run this."<<"\n";
        return 1;
    }
    else
    {
        cout<<"SIP is disabled."<<"\n";
    }
    cout<<"Starting analyzer."<<"\n";
    Analyzer();
    return 0;
}

bool is_sip_enabled()
{
    bool is_sip_enabled;
    FILE *fp;
    char output_char[100];
    fp=popen("csrutil status","r");
    if(fp==NULL)
    {
        cerr<<"Failed to get csrutil status."<<"\n";
        exit(1);
    }
    while(fgets(output_char,sizeof(output_char),fp)!=0)
    {
        
    }
    pclose(fp);
    string output=output_char;
    string control="System Integrity Protection status: enabled.";
    //cout<<output<<"\n";
    //cout<<control<<"\n";
   // if(output==control)
    if(output.compare(control)==0)
    {
        is_sip_enabled=true;
        return is_sip_enabled;
    }
    is_sip_enabled=false;
    return is_sip_enabled;
}
