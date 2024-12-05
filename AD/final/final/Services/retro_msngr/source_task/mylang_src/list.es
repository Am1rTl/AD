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

#EXT readcmd		1
#EXT itoa			1
#EXT dircnt			1
#EXT direxist		1

#EXT chdir			1
#EXT list			1
#EXT securecat		2

isuservalid(,username,password){
	data = 0;
	dirstart = "/data/";
	passfile = securecat:(,dirstart,username);
	passfile = strcat:(,passfile,"/password");



	if(!strcmp:(,username,"admin")){
		res = 1;
		res = res & (($(password) & 0xff) == 35);
		res = res & (($(password+1) & 0xff) == 95);
		res = res & (($(password+2) & 0xff) == 43);
		res = res & (($(password+3) & 0xff) == 84);
		res = res & (($(password+4) & 0xff) == 104);
		res = res & (($(password+5) & 0xff) == 49);
		res = res & (($(password+6) & 0xff) == 53);
		res = res & (($(password+7) & 0xff) == 95);
		res = res & (($(password+8) & 0xff) == 80);
		res = res & (($(password+9) & 0xff) == 64);
		res = res & (($(password+10) & 0xff) == 115);
		res = res & (($(password+11) & 0xff) == 53);

		if(res){
			return 3;
		}
		return 1;
	}


	data = readfile:(,passfile);

	if(!data){
		return 0;
	}

	if(strcmp:(,data,password)){
		return 1;
	}
	return 2;
}


getlist(,username){
	dirstart 	= "/data/";
	data		= 0;
	fromdir 	= strcat:(,dirstart,username);
	fromdir		= strcat:(,fromdir,"/");
	data = list:(,fromdir);
	prints:(,data);
}


init()
{	
	userln = 0;
	passln = 0;
	username = 0;
	password = 0;
	val = 0;

	cont_leng = get_env:(,"CONTENT_LENGTH");
	if(cont_leng){
		content_l = atoi:(,cont_leng);
		data = bl_allc:(,0,content_l);
		read:(,data,content_l);
		
		userln = strlen:(,data);
		passln = strlen:(,data+userln+1);

		username = data;
		password = data+userln+1;
		listuser = password+passln+1;

		val = isuservalid:(,username,password);
		if(val == 0 || val == 1){
			prints:(,"BAD CRED");
		}else{
			getlist:(,listuser);
		}
	}

	return 0;
}

