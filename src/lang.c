#include "lang.h"

#include <stdio.h>
#include <glib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef LXDM_DATA_DIR
#define LXDM_DATA_DIR	"/usr/share/lxdm"
#endif

void lxdm_load_langs(void *arg,void (*cb)(void *arg,char *lang,char *desc))
{
	FILE *fp;
	cb(arg,"","Default");
	fp=fopen(LXDM_DATA_DIR "/lang.txt","r");
	if(!fp)
		return;
	while(1)
	{
		char lang[32],desc[128],*p;
		p=fgets(lang,sizeof(lang),fp);
		if(!p) break;
		p=strchr(lang,'\n');if(p) *p=0;
		if(!lang[0]) continue;
		p=fgets(desc,sizeof(desc),fp);
		if(!p) break;
		p=strchr(desc,'\n');if(p) *p=0;
		if(!desc[0]) continue;
		cb(arg,lang,desc);
	}
	fclose(fp);
}
