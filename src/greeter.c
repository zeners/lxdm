/*
 *      lxdm-ui.c
 *      
 *      Copyright 2009 PCMan <pcman.tw@gmail.com>
 *      
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <glib/gi18n.h>

#include "lang.h"

#define XSESSION_DIR    "/usr/share/xsessions"

#ifndef LXDM_DATA_DIR
#define LXDM_DATA_DIR	"/usr/share/lxdm"
#endif

static GKeyFile *config;
static GtkWidget* win;
static GtkWidget* prompt;
static GtkWidget* login_entry;
static GtkWidget* prompt;

static GtkWidget* sessions;
static GtkWidget* lang;

static GtkWidget* exit;

static GtkWidget* exit_menu;

static char* user = NULL;
static char* pass = NULL;
static char* session_exec = NULL;
static char* session_desktop_file = NULL;

static GdkPixbuf *bg_img = NULL;
static GdkColor bg_color = {0};

static GIOChannel *greeter_io;

static void do_reboot(void)
{
	printf("reboot\n");
	fflush(stdout);
}

static void do_shutdown(void)
{
	printf("shutdown\n");
	fflush(stdout);
}

static void on_screen_size_changed(GdkScreen* scr, GtkWindow* win)
{
    gtk_window_resize(win, gdk_screen_get_width(scr), gdk_screen_get_height(scr));
}

static void on_entry_activate(GtkEntry* entry, gpointer user_data)
{
	if(!user)
	{
		user = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
		gtk_entry_set_text(GTK_ENTRY(entry), "");
		gtk_label_set_text(GTK_LABEL(prompt), _("Password:"));
		if(strchr(user,' '))
		{
			g_free(user);
			user=NULL;
			return;
		}
		gtk_entry_set_visibility(entry, FALSE);
	}
	else
	{
		GtkTreeIter it;
		char *session_lang=0;
		
		if(gtk_combo_box_get_active_iter(GTK_COMBO_BOX(sessions), &it))
		{
			GtkTreeModel* model = gtk_combo_box_get_model(GTK_COMBO_BOX(sessions));
			gtk_tree_model_get(model, &it, 1, &session_exec, 2, &session_desktop_file, -1);
		}
		else
		{
			/* FIXME: fatal error */
		}
		
		pass = g_strdup( gtk_entry_get_text(entry));
		if(strchr(pass,' '))
		{
			g_free(user);user=NULL;
			g_free(pass);pass=NULL;
			gtk_label_set_text(GTK_LABEL(prompt), _("User:"));
			gtk_entry_set_text(GTK_ENTRY(entry), "");
			gtk_entry_set_visibility(GTK_ENTRY(entry), TRUE);
			return;		
		}
		if(gtk_combo_box_get_active_iter(GTK_COMBO_BOX(lang), &it))
		{
			GtkTreeModel* model = gtk_combo_box_get_model(GTK_COMBO_BOX(lang));
			gtk_tree_model_get(model, &it, 1, &session_lang, -1);	
		}

		printf("login user=%s pass=%s session=%s lang=%s\n",
			user,pass,session_exec,session_lang);
		fflush(stdout);

		/* password check failed */
		g_free(user);
		user = NULL;
		g_free(pass);
		pass = NULL;
		
		gtk_widget_hide(prompt);
		gtk_widget_hide(GTK_WIDGET(entry));

		gtk_label_set_text(GTK_LABEL(prompt), _("User:"));
		gtk_entry_set_text(GTK_ENTRY(entry), "");
		gtk_entry_set_visibility(GTK_ENTRY(entry), TRUE);
	}
}

static void load_sessions()
{
    GtkListStore* list;
    GtkTreeIter it, active_it = {0};
    char* last;
    char *path, *file_name, *name, *exec;
    GKeyFile* kf;
    GtkCellRendererText* render;
    GDir* dir = g_dir_open(XSESSION_DIR, 0, NULL);
    if(!dir)
        return;

    last = g_key_file_get_string(config, "base", "last_session", NULL);

    list = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    kf = g_key_file_new();
    while((file_name = (char*)g_dir_read_name(dir))!=NULL)
    {
        path = g_build_filename(XSESSION_DIR, file_name, NULL);
        if(g_key_file_load_from_file(kf, path, 0, NULL))
        {
            name = g_key_file_get_locale_string(kf, "Desktop Entry", "Name", NULL, NULL);
            exec = g_key_file_get_string(kf, "Desktop Entry", "Exec", NULL);
            if(!strcmp(name,"LXDE"))
            	gtk_list_store_prepend(list, &it);
            else
            	gtk_list_store_append(list, &it);
            gtk_list_store_set(list, &it, 0, name, 1, exec, 2, file_name, -1);

            if(last && strcmp(file_name, last)==0)
                active_it = it;

            g_free(name);
            g_free(exec);
        }
        g_free(path);
    }
    g_dir_close(dir);
    g_key_file_free(kf);
    
	gtk_list_store_prepend(list, &it);
	gtk_list_store_set(list, &it, 0, _("Default"), 1, "", 2, "__default__", -1);
	if(last && strcmp(file_name, last)==0)
		active_it = it;
    
    g_free(last);

    render = (GtkCellRendererText*)gtk_cell_renderer_text_new();
    gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(sessions), GTK_CELL_RENDERER(render), TRUE);
    gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(sessions), GTK_CELL_RENDERER(render), "text", 0, NULL);

    gtk_combo_box_set_model(GTK_COMBO_BOX(sessions), GTK_TREE_MODEL(list));
    if(active_it.stamp)
    	gtk_combo_box_set_active_iter(GTK_COMBO_BOX(sessions), &active_it);
    else
    	gtk_combo_box_set_active(GTK_COMBO_BOX(sessions),0);

    g_object_unref(list);
}

static void load_lang_cb(void *arg,char *lang,char *desc)
{
	GtkListStore* list=(GtkListStore*)arg;
	GtkTreeIter it;
	gtk_list_store_append(list, &it);
	gtk_list_store_set(list, &it, 0, desc, 1, lang, -1);	
}

static void load_langs()
{
	GtkListStore* list;
	GtkCellRendererText* render;
	list = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
	lxdm_load_langs(list,load_lang_cb);
	render = (GtkCellRendererText*)gtk_cell_renderer_text_new();
	gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(lang), GTK_CELL_RENDERER(render), TRUE);
	gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(lang), GTK_CELL_RENDERER(render), "text", 0, NULL);
	gtk_combo_box_set_model(GTK_COMBO_BOX(lang), GTK_TREE_MODEL(list));
	gtk_combo_box_set_active(GTK_COMBO_BOX(lang),0);
	g_object_unref(list);
}

static void on_exit_clicked(GtkButton* exit_btn, gpointer user_data)
{
    gtk_menu_popup(GTK_MENU(exit_menu), NULL, NULL, NULL, NULL,
                   0, gtk_get_current_event_time());
}

static void load_exit()
{
    GtkWidget* item;
    exit_menu = gtk_menu_new();
    item = gtk_image_menu_item_new_with_mnemonic(_("_Reboot"));
    g_signal_connect(item, "activate", G_CALLBACK(do_reboot), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(exit_menu), item);

    item = gtk_image_menu_item_new_with_mnemonic(_("_Shutdown"));
    g_signal_connect(item, "activate", G_CALLBACK(do_shutdown), NULL);
    gtk_menu_shell_append(GTK_MENU_SHELL(exit_menu), item);

    gtk_widget_show_all(exit_menu);
    g_signal_connect(exit, "clicked", G_CALLBACK(on_exit_clicked), NULL);
}

static gboolean on_expose(GtkWidget* widget, GdkEventExpose* evt, gpointer user_data)
{
	cairo_t *cr;

	if(!GTK_WIDGET_REALIZED(widget))
        return FALSE;
    cr = gdk_cairo_create(widget->window);
    if(bg_img)
    {
        cairo_matrix_t matrix;
        double x=-0.5,y=-0.5,sx,sy;
        cairo_get_matrix(cr,&matrix);
        sx=(double)gdk_screen_width()/(double)gdk_pixbuf_get_width(bg_img);
        sy=(double)gdk_screen_height()/(double)gdk_pixbuf_get_height(bg_img);
        cairo_scale(cr,sx,sy);
        gdk_cairo_set_source_pixbuf(cr,bg_img,x,y);
        cairo_paint(cr);
        cairo_set_matrix(cr,&matrix);
    }
    else
    {
        gdk_cairo_set_source_color(cr, &bg_color);
        cairo_rectangle(cr,0,0,gdk_screen_width(),gdk_screen_height());
        cairo_fill(cr);
    }
    cairo_destroy(cr);
    return FALSE;
}

static void create_win()
{
    GtkBuilder* builder;
    GdkScreen* scr;
    builder = gtk_builder_new();
    gtk_builder_add_from_file(builder, LXDM_DATA_DIR "/lxdm.glade", NULL);
    win = (GtkWidget*)gtk_builder_get_object(builder, "lxdm");
    GTK_WIDGET_SET_FLAGS(win, GTK_APP_PAINTABLE);
    g_signal_connect(win, "expose-event", G_CALLBACK(on_expose), NULL);

    scr = gtk_widget_get_screen(win);
    g_signal_connect(scr, "size-changed", G_CALLBACK(on_screen_size_changed), win);

    prompt = (GtkWidget*)gtk_builder_get_object(builder, "prompt");
    login_entry = (GtkWidget*)gtk_builder_get_object(builder, "login_entry");

    g_signal_connect(login_entry, "activate", G_CALLBACK(on_entry_activate), NULL);


    sessions = (GtkWidget*)gtk_builder_get_object(builder, "sessions");
    load_sessions();

    lang = (GtkWidget*)gtk_builder_get_object(builder, "lang");
    load_langs();

    exit = (GtkWidget*)gtk_builder_get_object(builder, "exit");
    load_exit();

    g_object_unref(builder);

    gtk_window_set_default_size(GTK_WINDOW(win), gdk_screen_get_width(scr), gdk_screen_get_height(scr));
    gtk_window_present(GTK_WINDOW(win));
    gtk_widget_realize(login_entry);
    gdk_keyboard_grab(login_entry->window,FALSE,GDK_CURRENT_TIME);
    gtk_widget_grab_focus(login_entry);
}

int ui_set_bg(void)
{
	char *bg;
	char *style;
	GdkWindow* root = gdk_get_default_root_window();
    GdkCursor* cursor = gdk_cursor_new(GDK_LEFT_PTR);

    gdk_window_set_cursor(root, cursor);

	bg=g_key_file_get_string(config,"display","bg",0);
	if(!bg)
        bg=g_strdup("#222E45");
	style=g_key_file_get_string(config,"display","bg_style",0);
	if(bg && bg[0]!='#')
	{
		GdkPixbuf *pb=gdk_pixbuf_new_from_file(bg,0);
		if(!pb)
		{
			g_free(bg);
			bg=g_strdup("#222E45");
		}
		else
		{
			bg_img=pb;
		}
	}
	if(bg && bg[0]=='#')
	{
		gdk_color_parse(bg,&bg_color);
		//gdk_window_set_background(win,&screen);
	}
	g_free(bg);
	g_free(style);
	return 0;
}

static gboolean greeter_input(GIOChannel *source,GIOCondition condition,gpointer data)
{
	GIOStatus ret;
	char *str;

	if(!(G_IO_IN&condition))
		return FALSE;
	ret=g_io_channel_read_line(source,&str,NULL,NULL,NULL);
	if(ret!=G_IO_STATUS_NORMAL)
		return FALSE;

	if(!strncmp(str,"quit",4))
	{
		gtk_main_quit();
	}
	else if(!strncmp(str,"reset",5))
	{
		gtk_widget_show(prompt);
		gtk_widget_show(login_entry);
		gtk_widget_grab_focus(login_entry);
	}
	g_free(str);
	return TRUE;
}

void listen_stdin(void)
{
	greeter_io=g_io_channel_unix_new(0);
	g_io_add_watch(greeter_io,G_IO_IN,greeter_input,NULL);
}

int gtk_ui_main(void)
{
	/* set gtk+ theme */
	char* gtk_theme = g_key_file_get_string(config, "display", "gtk_theme", NULL);
	if(gtk_theme)
	{
		GtkSettings* settings = gtk_settings_get_default();
		g_object_set(settings, "gtk-theme-name", gtk_theme, NULL);
		g_free(gtk_theme);
	}

	/* create the login window */
	create_win();
	listen_stdin();
	gtk_main();

	return 0;
}

void ui_set_root_bg(void)
{
	char *p;
	GdkWindow *root=gdk_get_default_root_window();
	GdkColor screen;
	GdkPixbuf *bg_img;

	/* get background */
	p=g_key_file_get_string(config,"display","bg",0);
	if(!p) p=g_strdup("#222E45");
	if(p && p[0]!='#')
	{
		GdkPixbuf *pb=gdk_pixbuf_new_from_file(p,0);
		if(!pb)
		{
			g_free(p);
			p=g_strdup("#222E45");
		}
		else
		{
			bg_img=pb;
		}
	}
	if(p && p[0]=='#')
	{
		gdk_color_parse(p,&screen);
	}
	g_free(p);

	/* set background */
	if(!bg_img)
	{
		GdkColormap *map = (GdkColormap*)gdk_window_get_colormap(root);
		gdk_color_alloc(map, &screen);
		gdk_window_set_background(root,&screen);
	}
	else
	{
		GdkPixmap *pix=NULL;
		p=g_key_file_get_string(config,"display","bg_style",0);
		if(!p || !strcmp(p,"stretch"))
		{
			GdkPixbuf *pb=gdk_pixbuf_scale_simple(bg_img,
					gdk_screen_width(),
					gdk_screen_height(),
					GDK_INTERP_HYPER);
			g_object_unref(bg_img);
			bg_img=pb;
		}
		g_free(p);
		gdk_pixbuf_render_pixmap_and_mask(bg_img,&pix,NULL,0);
		g_object_unref(bg_img);
		/* call x directly, because gdk will ref the pixmap */
		//gdk_window_set_back_pixmap(root,pix,FALSE);
		XSetWindowBackgroundPixmap(GDK_WINDOW_XDISPLAY(root),
				GDK_WINDOW_XID(root), GDK_PIXMAP_XID(pix));
		g_object_unref(pix);
	}
	gdk_window_clear(root);
}

int main(int arc,char *arg[])
{
	config=g_key_file_new();
	g_key_file_load_from_file(config,"/etc/lxdm/lxdm.conf",0,0);
	gtk_init(&arc,&arg);
	ui_set_bg();
	ui_set_root_bg();
	gtk_ui_main();
	return 0;
}
