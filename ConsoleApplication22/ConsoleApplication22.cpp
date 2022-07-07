#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
int gtfo(const char* text = "")
{
    printf("gtfo! (%s)\n", text);
    return -1;
}
void entropy(std::string fileName) {
    fstream f;

    

    long total = 0;

    int code[256] = { 0 };

    float entr = 0,  prob;

    f.open(fileName.c_str(), ios::in | ios::binary);

    if (!f)

    {

        cout << "Error 1: open input file " << fileName << endl;

        exit(0);

    }

    char ch;

    f.unsetf(ios::skipws);

    while (!f.eof())

    {

        f >> ch;

        if (!f.eof())

        {

            code[(int)ch]++;

            total++;

        }

    }

    f.close();

    for (int i = 0; i < 256; i++)

    {

        if (code[i] == 0)

            continue;

        prob = code[i] / (float)total;

        entr -= prob * log(prob) / log(2.0f);

    }

    cout << "Bytes: " << total << endl;

    cout.setf(ios::fixed);

    cout.precision(3);

    cout << "Entropy: " << entr << endl;

    cout.precision(10);

}
int main(int argc, char* argv[])
{
    int count = 0;
   
    if (argc < 2)
        return gtfo("argc");
    std::string str;
    std::cin >> str;
    
    auto hFile = CreateFileA(str.std::string::c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    
    auto hMappedFile = CreateFileMappingA(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    
    auto fileMap = MapViewOfFile(hMappedFile, FILE_MAP_READ, 0, 0, 0);
    
    auto pidh = PIMAGE_DOS_HEADER(fileMap);
    
    auto pnth = PIMAGE_NT_HEADERS(ULONG_PTR(fileMap) + pidh->e_lfanew);

    auto importDir = pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    puts("Import Directory");
    printf(" RVA: %08X\n", importDir.VirtualAddress);
    printf("Size: %08X\n\n", importDir.Size);

    auto importDescriptor = PIMAGE_IMPORT_DESCRIPTOR(ULONG_PTR(fileMap) + importDir.VirtualAddress);
    char ch;
    while (true) {
        
        std::cout << "Print next? y/n: ";
        std::cin >> ch;
        if(ch == 'y') {
            system("cls");
            break;
        }
        else if (ch == 'n') {
            exit(0);
        }
        
    }
    if (!IsBadReadPtr((char*)fileMap + importDir.VirtualAddress, 0x1000))
    {
        for (; importDescriptor->FirstThunk; importDescriptor++)
        {
            printf("OriginalFirstThunk: %08X\n", importDescriptor->OriginalFirstThunk);
            printf("     TimeDateStamp: %08X\n", importDescriptor->TimeDateStamp);
            printf("    ForwarderChain: %08X\n", importDescriptor->ForwarderChain);
            if (!IsBadReadPtr((char*)fileMap + importDescriptor->Name, 0x1000)) {
                printf("              Name: %08X \"%s\"\n", importDescriptor->Name, (char*)fileMap + importDescriptor->Name);
            }
            else {
                printf("              Name: %08X INVALID\n", importDescriptor->Name);
                printf("              Name: %08X\n", importDescriptor->Name);
                printf("        FirstThunk: %08X\n", importDescriptor->FirstThunk);
            }
            auto thunkData = PIMAGE_THUNK_DATA(ULONG_PTR(fileMap) + importDescriptor->FirstThunk);
            for (; thunkData->u1.AddressOfData; thunkData++)
            {
                auto rva = ULONG_PTR(thunkData) - ULONG_PTR(fileMap);

                auto data = thunkData->u1.AddressOfData;
                
                    auto importByName = PIMAGE_IMPORT_BY_NAME(ULONG_PTR(fileMap) + data);
                    if (!IsBadReadPtr(importByName, 0x1000)) {
                        printf("             Function: %08X \"%s\"\n", data, (char*)importByName->Name);
                        for (int i=0; ; i++)
                        {
                            if (importByName->Name[i]=='w' || importByName->Name[i] == 'W')
                            {
                                count++;
                                break;
                            }
                            if (importByName->Name[i] == '\0')
                            {
                                break;
                            }
                        }
                    }
                    else {
                        printf("             Function: %08X INVALID\n", data);
                    }
                
            }

            cout << "";
        }
    }
    else {
        cout << "INVALID IMPORT DESCRIPTOR" << endl;
    }
    cout << "count: " << count << endl;
    char chr;
    while (true) {

        cout << "Print next? y/n: ";
        cin >> chr;
        if (chr == 'y') {
            system("cls");
            break;
        }
        else if (chr == 'n') {
            exit(0);
        }
    }
   
    
    entropy(str);

    return 0;
}