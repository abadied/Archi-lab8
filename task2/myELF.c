#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
 #include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "elf.h"
#include <sys/mman.h>

 struct func_desc{
    char *name;
    void (*fun)();
};

struct stat fd_stat;

int current_fd = -1;
int debug_mode = 0;
void* map_start = MAP_FAILED;

void quit(){
    close(current_fd);
    exit(0);
}

void examineElfFile(){
    printf("Enter File name: \n");
    char filename[100];
    char c;
    int i = 0;
    while((c = fgetc(stdin))!=EOF && i < 100){
        if(c == '\n'){
            filename[i] = 0;
            break;
        }
        filename[i] = c;
        i++;
    }
    printf("\n");
    if(current_fd != -1){
        close(current_fd);
        current_fd = -1;
    }
    if(((current_fd = open(filename, O_RDWR)) < 0)){
        perror("error in open \n");
        exit(-1);
    }
    if( fstat(current_fd, &fd_stat) != 0){
        perror("stat failed \n");
        exit(-1);
    }
    if (map_start != MAP_FAILED){
        munmap(map_start, fd_stat.st_size);
    }
    if ( (map_start = mmap(0, fd_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, current_fd, 0)) == MAP_FAILED ) {
        perror("mmap failed \n");
        exit(-4);
    }
    Elf32_Ehdr *header;
    header = (Elf32_Ehdr*)map_start;
    unsigned char* ident = header->e_ident;
    int entry_point = header->e_entry;
    int sh_off = header->e_shoff;
    short shnum = header->e_shnum;
    short shent_size = header->e_shentsize;
    int ph_off = header->e_phoff;
    short phnum = header->e_phnum;
    short phent_size = header->e_phentsize;
    printf("Magic numbers: \t\t\t%02x %02x %02x \n",*(ident + 1),*(ident + 2),*(ident + 3));
    if (*(ident + 5) == 1)
        printf("Data encoding: \t\t\tLittle endian\n");
    else if (*(ident + 5) == 2)
        printf("Data encoding: \t\t\tBig endian\n");
    else
        printf("Data encoding: \t\t\tERROR\n");
    printf("Entry point: \t\t\t0x%08x \n",entry_point);
    printf("Section header offset: \t\t%d\n",sh_off);
    printf("Number of section headers: \t%hd\n",shnum);
    printf("Size of section header: \t%hd\n",shent_size);
    printf("Program header offset: \t\t%d\n",ph_off);
    printf("Number of program headers: \t%hd\n",phnum);
    printf("Size of program header: \t%hd\n\n",phent_size);
}

void printSectionNames(){
    if (map_start == MAP_FAILED) {
        printf("no file opened\n");
        return;
    }
    Elf32_Ehdr *elfheader;
    elfheader = (Elf32_Ehdr*)map_start;
    
    short shnum = elfheader->e_shnum;
    short shent_size = elfheader->e_shentsize;

    void* map_sheaders = (void*)((char*)map_start + elfheader->e_shoff);
    
    Elf32_Shdr* strsechead = (Elf32_Shdr*)((char*)map_sheaders + (elfheader->e_shstrndx)*shent_size);
    char* strtable = (char*)map_start + strsechead->sh_offset;
    
    printf("%s\n",strtable + 1);

    Elf32_Shdr *sheader;
    int i;
    for (i = 0; i < shnum; i++) {
        sheader = (Elf32_Shdr*)((char*)map_sheaders + shent_size*i);
        printf("[%d]\t",i);
        printf("%s\t", (strtable + sheader->sh_name));
        printf("%08x\t", sheader->sh_addr);
        printf("%06x\t",sheader->sh_offset);
        printf("%06x\t",sheader->sh_size);
        printf("%d\n", sheader->sh_type);
    }
}

void printsyms(int tabsize, void *map_tab, char* symstrtab, char* shstrtab, void* map_sheaders) {
	
}

void printSymbols(){
    if (map_start == MAP_FAILED) {
        printf("no file opened\n");
        return;
    }
    
    Elf32_Ehdr *elfheader;
    elfheader = (Elf32_Ehdr*)map_start;

    short shnum = elfheader->e_shnum;
    short shent_size = elfheader->e_shentsize;

    void* map_sheaders = (void*)((char*)map_start + elfheader->e_shoff);

	Elf32_Shdr* strsechead = (Elf32_Shdr*)((char*)map_sheaders + (elfheader->e_shstrndx)*shent_size);
    char* strtable = (char*)map_start + strsechead->sh_offset;

    Elf32_Shdr *sheader;

	int i;
    for (i = 0; i < shnum; i++) {
        sheader = (Elf32_Shdr*)((char*)map_sheaders + shent_size*i);
        if (sheader->sh_type == 2 || sheader->sh_type == 11) {

        	Elf32_Shdr *strsec = (Elf32_Shdr*)((char*)map_sheaders + ((sheader->sh_link) * shent_size));

        	int tabsize = (sheader->sh_size) / 16;
    		void* map_tab = (void*)((char*)map_start + sheader->sh_offset);
        	char* symstrtab = (char*)map_start + strsec->sh_offset;
        	
        	Elf32_Sym *symtab_ent;
			int j;
			for (j = 0; j < tabsize; j++) {
		        symtab_ent = (Elf32_Sym*)((char*)map_tab + 16*j);
		        printf("[%d]\t",j);
		        printf("%08x\t", symtab_ent->st_value);
		        if (symtab_ent->st_shndx == 0) {
		        	printf("UND\t\t\t");
		        }
		        else if (symtab_ent->st_shndx == 0xfff1) {
		        	printf("ABS\t\t\t");
		        }
		        else {
		        	int idx = symtab_ent->st_shndx;

					Elf32_Shdr* sec = (Elf32_Shdr*)((char*)map_sheaders + idx*shent_size);

		        	printf("%d\t", idx);
		        	printf("%s\t\t", (strtable + sec->sh_name));
		        }
		        printf("%s\n",(symstrtab + symtab_ent->st_name));
		    }
		    printf("\n");
        }
    }
}

void toggleDebugMode(){
	if(debug_mode == 1){
		debug_mode = 0;
		printf("Debug flag now off.\n");
	}
	else{
		debug_mode = 1;
		printf("Debug flag now on.\n");
	}
}


int main(int argc, char** argv){
    char c;
    char empty;
    struct func_desc menu[] = {	{"0-Toggle Debug Mode", toggleDebugMode},
    							{"1-Examine ELF File", examineElfFile},
    							{"2-Print section names",printSectionNames},
    							{"3-Print Symbols",printSymbols},
    							{"4-Quit", quit},
    							{NULL,NULL}};
    while(1){
    	if(debug_mode){
    		printf("Debugging");
    	}

        printf("Please choose a function: \n");
        for(int i = 0; i < 5; i++){
            printf("%s \n",menu[i].name);
        }
    	
        c = fgetc(stdin);
        empty = fgetc(stdin);
        while (empty != EOF && empty != '\n'){empty = fgetc(stdin);}
        if( c >= '0' && c <= '4'){
            menu[c - '0'].fun();
        }
        else{
            printf("Not within bounds \n");
        }
        
    }
    
}