#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <fcntl.h>
#include <signal.h>

#define FREE 0
#define USING 1
#define SIZE_OF_NOTES 0x0f

struct note{
	char buf[0x10];
};

char *notes[SIZE_OF_NOTES];
int states[SIZE_OF_NOTES];

int fd;
int re_entry;
char name[0x90];
char *key;
int reentry;

void myputs(const char *str, int newline){
	int len = 0;
	while(str[len++]);
	len--;
	write(1, str, len);
	if(newline)
		write(1, "\n", 1);
}

void alarmHandler(){
	myputs("time out", 1);
	exit(0);
}

void initProc(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGALRM, alarmHandler);
	alarm(30);
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	struct sock_filter sfi[] = {
        {0x20,0x00,0x00,0x00000004},
        {0x15,0x00,0x05,0xc000003e},
        {0x20,0x00,0x00,0x00000000},
        {0x35,0x00,0x01,0x40000000},
        {0x15,0x00,0x02,0xffffffff},
        {0x15,0x01,0x00,0x0000003b},
    	{0x06,0x00,0x00,0x7fff0000},
    	{0x06,0x00,0x00,0x00000000},
    };
    struct sock_fprog sfp = {8,sfi};
	prctl(PR_SET_SECCOMP,2,&sfp);
}

int getContent(char *buf, int size){
	int ret;
	int i;
	for(i = 0; i < size; i++)
	{
		ret = read(0, &buf[i], 1);
		if(ret == -1)
			exit(0);
		if(buf[i] == '\n')
		{
			return i+1;
		}
	}	
	return i;
}

int getNumber(){
	char buf[0x10];
	getContent(buf, 0x10);	
	return atoi(buf);
}


void putsMenu(){
	myputs("----------------------", 1);
	myputs("1.add note", 1);
	myputs("2.delete note", 1);
	myputs("3.encrypt note", 1);
	myputs(">>", 0);
}

void addNote(){
	int size;
	int i;
	for(i = 0; i < SIZE_OF_NOTES; i++){
		if(notes[i] == NULL)
			break;
	}	
	if(i == SIZE_OF_NOTES){
		myputs("full!", 1);
		return;	
	}
	
	notes[i] = (char *)malloc(sizeof(struct note));

	myputs("size of your note >>", 0);
	size = getNumber();
	size = (size > 0x18 || size < 0)? 0x18:size;	

	if(notes[i] == NULL)
	{
		myputs("error in malloc note", 1);
		exit(0);
	}
	myputs("input your content >>", 0);	
	getContent(notes[i], size);
	
	states[i] = USING;	
	myputs("success", 1);
	return;	
}

void deleteNote(){
	int i;
	myputs("input the index to delete >>", 0);
	i = getNumber();
	if(i < 0 || i > SIZE_OF_NOTES)
	{
		myputs("out of index", 1);	
		return;
	}
	if(notes[i] != NULL)
	{
		free(notes[i]);	
		states[i] = FREE;
		myputs("complete", 1);
	}
	else
	{
		myputs("in using", 1);
		return;	
	}
}

void doSomeThing(char *seed, int index){
	if(index > SIZE_OF_NOTES || index < 0 || states[index] == FREE)
		return;
	unsigned char start = seed[index];
	for(int i = 0; i < 0x10; i++)
	{
		notes[index][i] = notes[index][i] ^ key[start+i];
	}

	myputs("success", 1);

}

void encryptNode(){
	char seed[0x50];
	int size;
	int index;
	myputs("input the index to encrypt >>", 0);
	index = getNumber();
	myputs("input the size of the seed (max 0x50) >>", 0);
	size = getNumber();
	if(size < 0 || size > 0x70)
	    size = 0x70;
	myputs("input the crypt seed >>", 0);
	getContent(seed, size);
	doSomeThing(seed, index);
}

int main()
{
	int choice;
	initProc();
	myputs("---------------------------", 1);
	myputs("welcome to D^3 CTF", 1);
	myputs("---------------------------", 1);
	myputs("your name: ", 0);
	fd = open("/dev/urandom", O_RDONLY);	
	if(fd == -1)
	{
		myputs("error in opening /dev/urandom", 1);	
		exit(0);
	}

	scanf("%90s", name);
	printf("welcome!%s.\n", name);

	key = (char*)malloc(0x300);
	if(key == NULL)
	{
		myputs("error in malloc key", 1);
		exit(0);	
	}
	
	if(!re_entry){
        re_entry = 1;
    }else{
        myputs("re_entry detected!", 1);
        exit(0);
    }
    
	if(read(fd, key, 0x300) != 0x300)
	{
		myputs("error in reading /dev/urandom", 1);
		exit(0);	
	}
	close(fd);
	
	while(1){
		putsMenu();
		choice = getNumber();			
		switch(choice){
		case 1:
			addNote();
			break;
		case 2:
			deleteNote();
			break;
		case 3:
			encryptNode();
			break;
		default:
			break;
		}
	}
	return 0;
}

