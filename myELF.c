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

int current_fd = -1;
int debug_mode = 0;

void quit(){
    close(current_fd);
    exit(0);
}

void examineElfFile(){
    printf("Enter File name: \n");
    char* filename;
    fgets(filename, 10, stdin);
    if(current_fd != -1){
        close(current_fd);
        current_fd = -1;
    }
    void* map_start;
    struct stat fd_stat;
    Elf32_Ehdr *header;
    int num_of_section_headers;
    if(((current_fd = open(filename, O_RDWR)) < 0)){
        perror("error in open \n");
        exit(-1);
    }
    if( fstat(current_fd, &fd_stat) != 0){
        perror("stat failed \n");
        exit(-1);
    }
    if ( (map_start = mmap(0, fd_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, current_fd, 0)) == MAP_FAILED ) {
        perror("mmap failed \n");
        exit(-4);
    }
    header = (Elf32_Ehdr*)map_start;
    num_of_section_headers = header->e_shnum;
    munmap(map_start, fd_stat.st_size);
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
    struct func_desc menu[] = {{"0-Toggle Debug Mode", toggleDebugMode},{"1-Examine ELF File", examineElfFile},{"2-Quit", quit},{NULL,NULL}};
    while(1){
    	if(debug_mode){
    		printf("Debugging");
    	}

        printf("Please choose a function: \n");
        for(int i = 0; i < 3; i++){
            printf("%s \n",menu[i].name);
        }
    	
        c = fgetc(stdin);
        empty = fgetc(stdin);
        while (empty != EOF && empty != '\n'){empty = fgetc(stdin);}
        if( c >= '0' && c <= '2'){
            menu[c - '0'].fun();
        }
        else{
            printf("Not within bounds \n");
        }
        
    }
    
}