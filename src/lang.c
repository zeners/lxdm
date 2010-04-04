/*
 *      lang.c - load language list
 *
 *      Copyright 2009 dgod <dgod.osa@gmail.com>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 3 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *      MA 02110-1301, USA.
 */

#include "lang.h"

#include <stdio.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef LXDM_DATA_DIR
#define LXDM_DATA_DIR   "/usr/share/lxdm"
#endif

#include "gdm/gdm-languages.h"

static char **lxdm_get_all_language_names(void)
{
	GPtrArray *array;
	FILE *fp;
	array=g_ptr_array_new();
	fp=fopen(LXDM_DATA_DIR "/lang.txt","r");
	if(fp)
	{
		char line[128];
		while(fgets(line,128,fp)!=NULL)
		{
			char *p=strchr(line,'\n');
			if(*p) *p=0;
			g_ptr_array_add(array,g_strdup(line));
		}
		fclose(fp);
	}
	g_ptr_array_add (array, NULL);
	return (char **) g_ptr_array_free (array, FALSE);
}

static char **lxdm_get_config_language_names(GKeyFile *config)
{
	char **list;

	list=g_key_file_get_string_list(config,"base","last_langs",NULL,NULL);
	if(!list)
	{
		list=g_malloc0(sizeof(char*));
	}
	return list;
}

void lxdm_load_langs(GKeyFile *config, gboolean all, void *arg, void (*cb)(void *arg, char *lang, char *desc))
{
    char **langs, **lang;

    cb(arg, "", _("Default")); /* default is to use the system wide settings ,not use the "C" */

    langs = all?lxdm_get_all_language_names():lxdm_get_config_language_names(config);
    for( lang = langs; *lang; ++lang )
    {
	char *normal=*lang;
        char* readable = gdm_get_language_from_name(normal, normal);
        cb(arg, normal, readable);
        g_free(readable);
    }
    g_strfreev(langs);

    if(!all) cb(arg,"~",_("More ..."));
}

