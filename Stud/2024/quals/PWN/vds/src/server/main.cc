#include <iostream>
#include <fcntl.h>
#include "vds.h"
#include "multiprocessing.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>

void child()  {
  void (*prog)() = (void(*)())mmap(0, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if((long)prog < 0){
    printf("%p\n",prog);
    puts("Cannot get memory for your program =(");
    exit(-1);
  }
  std::cout<<"Welcome to your vds vm!!!\n";
  std::cout<<"Enter your program x86_64 source.\n";
  std::cout<<">>\n";
  fgets((char*)prog,0x4000,stdin);
  prog();
  std::cout<<"Finished execution!!!\n";
  return;
}

void menu() {
  std::cout<<"Enter 1 to spawn your vm instance.\n";
  std::cout<<"Enter 2 to exit vds manager\n";
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
  char buf[10] = {0};
  std::cout<<"Vds server activated."<<"\n";
  int option = 0;
  while(true) {
    menu();
    fgets(buf,10,stdin);
    option = atoi(buf);
    switch(option){
      case 1:
        spawn_child(false, child);
        break;
      case 2:
        exit(0);
      break;
      default:
        std::cout<<"Invalid option\n";
      break;
    }
  }
  return 0;
}
