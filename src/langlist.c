#include <stdio.h>
#include <glib.h>
#include "gdm/gdm-languages.h"

int main(void)
{
	char **list,**lang;
	list=gdm_get_all_language_names();
	for(lang=list;*lang!=NULL;lang++)
	{
		char *normal=gdm_normalize_language_name(*lang);	
		printf("%s\n",normal);
		g_free(normal);
	}
	return 0;
}

