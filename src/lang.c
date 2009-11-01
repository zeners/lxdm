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

void lxdm_load_langs(void *arg,void (*cb)(void *arg,char *lang,char *desc))
{
	char **langs, **lang;
	cb(arg,"C","Default");

    /* come up with available languages with gdm-languages */
    langs = gdm_get_all_language_names();
    for(lang = langs; *lang; ++lang)
    {
        char* normal = gdm_normalize_language_name(*lang);
        char* readable = gdm_get_language_from_name(normal, normal);
        cb(arg, normal, readable);
        g_free(readable);
        g_free(normal);
    }
}
