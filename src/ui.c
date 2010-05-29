/*
 *      lxdm.c - basic ui of lxdm
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


#include <X11/Xlib.h>

#include <string.h>
#include <poll.h>
#include <grp.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#include <sys/wait.h>

#include "lxdm.h"

static pid_t greeter = -1;
static guint greeter_watch = 0;
static int greeter_pipe[2];
static GIOChannel *greeter_io;
static guint io_id;

void ui_drop(void)
{
    /* if greeter, do quit */
    if( greeter > 0 )
    {
        write(greeter_pipe[0], "exit\n", 5);
        g_source_remove(io_id);
        io_id = 0;
        g_io_channel_unref(greeter_io);
        greeter_io = NULL;
        close(greeter_pipe[1]);
        close(greeter_pipe[0]);

        g_source_remove(greeter_watch);
        greeter_watch=0;
        waitpid(greeter, 0, 0) ;
        greeter=-1;
    }
}

static void greeter_setup(gpointer user)
{
}

static gchar *greeter_param(char *str, char *name)
{
    char *temp, *p;
    char ret[128];
    int i;
    temp = g_strdup_printf(" %s=", name);
    p = strstr(str, temp);
    if( !p )
    {
        g_free(temp);
        return NULL;
    }
    p += strlen(temp);
    g_free(temp);
    for( i = 0; i < 127; i++ )
    {
        if( !p[i] || isspace(p[i]) )
            break;
        ret[i] = p[i];
    }
    ret[i] = 0;
    return g_strdup(ret);
}

static gboolean on_greeter_input(GIOChannel *source, GIOCondition condition, gpointer data)
{
    GIOStatus ret;
    char *str;

    if( !(G_IO_IN & condition) )
        return FALSE;
    ret = g_io_channel_read_line(source, &str, NULL, NULL, NULL);
    if( ret != G_IO_STATUS_NORMAL )
        return FALSE;

    if( !strncmp(str, "reboot", 6) )
        lxdm_do_reboot();
    else if( !strncmp(str, "shutdown", 6) )
        lxdm_do_shutdown();
    else if( !strncmp(str, "log ", 4) )
        log_print(str + 4);
    else if( !strncmp(str, "login ", 6) )
    {
        char *user = greeter_param(str, "user");
        char *pass = greeter_param(str, "pass");
        char *session = greeter_param(str, "session");
        char *lang = greeter_param(str, "lang");
        if( user && pass )
        {
            struct passwd *pw;
            int ret = lxdm_auth_user(user, pass, &pw);
            if( AUTH_SUCCESS == ret && pw != NULL )
            {
                ui_drop();
                lxdm_do_login(pw, session, lang);
                if( lxdm_cur_session() <= 0 )
                    ui_prepare();
            }
            else
                write(greeter_pipe[0], "reset\n", 6);
        }
        g_free(user);
        g_free(pass);
        g_free(session);
        g_free(lang);
    }
    g_free(str);
    return TRUE;
}

static void on_greeter_exit(GPid pid, gint status, gpointer data)
{
    if( pid != greeter )
        return;
    greeter = -1;
    greeter_watch=0;
}

void ui_prepare(void)
{
    char *p;

    /* if session is running */
    if( lxdm_cur_session() > 0 )
        return;

    /* if find greeter, run it */
    p = g_key_file_get_string(config, "base", "greeter", NULL);
    if( p && p[0] )
    {
        char **argv;
        gboolean ret;
        g_shell_parse_argv(p, NULL, &argv, NULL);
        
        /* FIXME: what's this? */
        if( greeter > 0 && kill(greeter, 0) == 0 )
            return;

        ret = g_spawn_async_with_pipes(NULL, argv, NULL,
                                       G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD, greeter_setup, 0,
                                       &greeter, greeter_pipe + 0, greeter_pipe + 1, NULL, NULL);
        g_strfreev(argv);
        if( ret == TRUE )
        {
            g_free(p);
            greeter_io = g_io_channel_unix_new(greeter_pipe[1]);
            io_id = g_io_add_watch(greeter_io, G_IO_IN | G_IO_HUP | G_IO_ERR,
                                   on_greeter_input, NULL);
            greeter_watch = g_child_watch_add(greeter, on_greeter_exit, 0);
            return;
        }
    }
    g_free(p);
}

int ui_main(void)
{
    GMainLoop *loop = g_main_loop_new(NULL, 0);
    ui_prepare();
    g_spawn_command_line_async("/etc/lxdm/LoginReady",NULL);
    g_main_loop_run(loop);
    return 0;
}

void ui_clean(void)
{
	if(greeter>0)
	{
		extern void stop_pid(int);
		g_source_remove(greeter_watch);
		stop_pid(greeter);
		greeter=-1;
	}
}

