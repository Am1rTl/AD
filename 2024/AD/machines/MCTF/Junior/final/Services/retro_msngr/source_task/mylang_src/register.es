#IMP inc/stdout
#IMP inc/bytelists

#EXT run_extern		...
#EXT get_env		1
#EXT atoi			1
#EXT read			2
#EXT mkdir			1
#EXT readfile		1

#EXT strstr			2
#EXT strcat			2
#EXT strlen			1
#EXT strcmp			2

#EXT writefile		2
#EXT securecat		2

reguser(,username,password){
	data = 0;
	passfile = 0;
	dirstart = "/data/";
	userdir = securecat:(,dirstart,username);


	if(!strcmp:(,username,"admin")){
		return 1;
	}


	if(mkdir:(,userdir)){
		return 1;
	}

	passfile = strcat:(,userdir,"/password");
	writefile:(,passfile,password);
	return 0;
}


init()
{	
	userln = 0;
	username = 0;
	password = 0;
	val = 0;

	cont_leng = get_env:(,"CONTENT_LENGTH");
	if(cont_leng){
		content_l = atoi:(,cont_leng);
		data = bl_allc:(,0,content_l);
		read:(,data,content_l);
		
		userln = strlen:(,data);

		username = data;
		password = data+userln+1;

		if(reguser:(,username,password)){
			prints:(,"USR EXIST");
		}else{
			prints:(,"USR REGISTERED");
		}
	}

	return 0;
}

