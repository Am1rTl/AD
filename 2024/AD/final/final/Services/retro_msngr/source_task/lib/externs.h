#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>


CELL ext_prints(CELL args[MAXARGS]){
	if(args[0]) printf("%s\n", args[0]);
	return 0;
}

CELL ext_printi(CELL args[MAXARGS]){
	printf("%p\n", args[0]);
	return 0;
}

CELL ext_bl_allc(CELL args[MAXARGS]){
	if(args[0]){
		void* ptr = (void*)(args[0]-4);
		HCEL len = getHCEL(ptr) + 5;
		BYTE* bl = (BYTE*)malloc(len);
		memcpy(bl, ptr, len);
		return (CELL)(bl+4);
	}else{
		BYTE* bl = (BYTE*)malloc(args[1]+5);
		memset(bl, 0, args[1]+5);
		setHCEL(bl, (HCEL)args[1]);
		return (CELL)(bl+4);
	}
}


CELL ext_get_env(CELL args[MAXARGS]){
	char* a = getenv(args[0]);
	if(!a) return 0;
	
	CELL ln = strlen(a);

	BYTE* bl = (BYTE*)malloc(ln+5);
	memset(bl, 0, ln+5);
	setHCEL(bl, ln);
	memcpy(bl+4, a, ln);
	return (CELL)(bl+4);
}

CELL ext_atoi(CELL args[MAXARGS]){
	return (CELL)atoi((char*)args[0]);
}

CELL ext_read(CELL args[MAXARGS]){
	return (CELL)read(0, (void*)args[0], (size_t)args[1]);
}

CELL ext_mkdir(CELL args[MAXARGS]){
	return mkdir(args[0], 0777);
}

CELL ext_readfile(CELL args[MAXARGS]){
	FILE *f = fopen(args[0], "rb");
	if(!f) return 0;

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET); 

	args[0] = 0;
	args[1] = fsize;

	BYTE* data = ext_bl_allc(args);
	fread(data, 1, fsize, f);
	fclose(f);

	return data;
}

CELL ext_strstr(CELL args[MAXARGS]){
	return strstr(args[0], args[1]);
}

char *str_replace(char *orig, char *rep, char *with) {
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep (the string to remove)
    int len_with; // length of with (the string to replace rep with)
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements

    // sanity checks and initialization
    if (!orig || !rep)
        return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0)
        return NULL; // empty rep causes infinite loop during count
    if (!with)
        with = "";
    len_with = strlen(with);

    // count the number of replacements needed
    ins = orig;
    for (count = 0; tmp = strstr(ins, rep); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
}

CELL ext_strcat(CELL args[MAXARGS]){
	CELL ln1 = strlen(args[0]);
	CELL ln2 = strlen(args[1]);

	BYTE* st = malloc(ln1+ln2+1);
	memset(st, 0, ln1+ln2+1);

	memcpy(st, args[0], ln1);
	memcpy(st+ln1, str_replace(args[1], "..", "."), ln2);
	return st;
}

CELL ext_securecat(CELL args[MAXARGS]){
	CELL ln1 = strlen(args[0]);
	CELL ln2 = strlen(args[1]);
	BYTE* st = malloc(ln1+ln2+1);
	memset(st, 0, ln1+ln2+1);

	BYTE* badchars = "!@#$%^&*(){}:|<>?'\";`,./-=+\\";
	BYTE* mystr = args[1];
	for(int i = 0;i<strlen(badchars);i++){
		for(int j = 0;j<ln2;j++){
			if(mystr[j] == badchars[i]){
				mystr[j] = '_';
			}
		}
	}

	memcpy(st, args[0], ln1);
	memcpy(st+ln1, args[1], ln2);
	return st;
}

CELL ext_strlen(CELL args[MAXARGS]){
	return strlen(args[0]);
}

CELL ext_strcmp(CELL args[MAXARGS]){
	return strcmp(args[0], args[1]);
}

CELL ext_writefile(CELL args[MAXARGS]){
	FILE *f = fopen(args[0], "w");
	if(!f) return -1;

	fwrite(args[1], 1, strlen(args[1]), f);
	fclose(f);
}

CELL ext_readcmd(CELL args[MAXARGS]){
	FILE *fp = popen(args[0], "r");
	BYTE* data[1024];
	BYTE* res = (BYTE*)malloc(1024);
	CELL len = 0;

	if(!fp) return 0;

	while(fread(data, 1, 1024, fp)){
		memcpy(res+len, data, 1024);
		len += 1024;
		res = realloc(res, len+1024);
	}
	return res;
}

CELL ext_itoa(CELL args[MAXARGS]){
	BYTE* dt = malloc(64);
	memset(dt, 0, 64);
	sprintf(dt, "%d", args[0]);
	return dt;
}

CELL ext_dircnt(CELL args[MAXARGS]){
	CELL file_count = 0;
	DIR * dirp;
	struct dirent * entry;

	dirp = opendir(args[0]);
	while ((entry = readdir(dirp)) != NULL) {
	    if (entry->d_type == DT_REG) {
	        file_count++;
	    }
	}
	closedir(dirp);

	return file_count;
}

CELL ext_direxist(CELL args[MAXARGS]){

	struct stat s;
	int err = stat(args[0], &s);
	if(-1 == err) {
		return 0;
	} else {
	    return 1;
	}
}

CELL ext_chdir(CELL args[MAXARGS]){
	return chdir(args[0]);
}

CELL ext_list(CELL args[MAXARGS]){
	CELL leng = 0;
	DIR * dirp;
	struct dirent * entry;

	BYTE* data = "";

	dirp = opendir(args[0]);
	while ((entry = readdir(dirp)) != NULL) {
	    if (entry->d_type == DT_DIR) {
	    	if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
	    	args[0] = data;
	    	args[1] = entry->d_name;
	    	data = ext_strcat(args);

	    	args[0] = data;
	    	args[1] = "\n";
	    	data = ext_strcat(args);
	    }
	}
	closedir(dirp);

	return data;
}