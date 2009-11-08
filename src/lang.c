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

#include "gdm/gdm-languages.h"

int lxdm_load_langs(void *arg,void (*cb)(void *arg,char *lang,char *desc), const char* last_lang)
{
    int ret = -1;
	char **langs, **lang;
    char* normal_last_lang;

	//cb(arg,"C","Default");
	cb(arg,"","Default"); /* default is to use the system wide settings ,not use the "C" */
    normal_last_lang = last_lang ? gdm_normalize_language_name(last_lang) : NULL;

    if(!normal_last_lang || !normal_last_lang[0])
        ret = 0;

    /* come up with available languages with gdm-languages */
    langs = gdm_get_all_language_names();
    for(lang = langs; *lang; ++lang)
    {
        char* normal = gdm_normalize_language_name(*lang);
        char* readable = gdm_get_language_from_name(normal, normal);
        cb(arg, normal, readable);
        if(ret < 0 && g_strcmp0(normal_last_lang, normal) == 0)
            ret = (lang - langs) + 1;
        g_free(readable);
        g_free(normal);
    }
    g_free(normal_last_lang);
    return ret;
}
