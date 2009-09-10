/* This file is not used in GTK+-based UI. Only left for reference. */

#define XLIB_ILLEGAL_ACCESS
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <gdk/gdkkeysyms.h>
#include <X11/Xlib.h>

#include <string.h>
#include <poll.h>

#include "lxdm.h"

#define MAX_INPUT_CHARS		32
#define MAX_VISIBLE_CHARS	14

static GdkWindow *win;
static PangoLayout *layout;
static char user[MAX_INPUT_CHARS];
static char pass[MAX_INPUT_CHARS];
static int stage;
static GdkRectangle rc;
static GdkColor bg,border,hint,text,msg;
static GdkColor screen;
static GdkPixbuf *bg_img;

static GSList *sessions;
static int session_select=-1;

static char *message;

static int get_text_layout(char *s,int *w,int *h)
{
	pango_layout_set_text(layout,s,-1);
	pango_layout_get_pixel_size(layout,w,h);
	return 0;
}

static void draw_text(cairo_t *cr,double x,double y,char *text,GdkColor *color)
{
	pango_layout_set_text (layout, text, -1);
	cairo_move_to(cr,x,y);
	gdk_cairo_set_source_color(cr,color);
	pango_cairo_show_layout(cr,layout);
}

static void on_expose(int e)
{
	cairo_t *cr=gdk_cairo_create(win);
	char *p=(stage==0)?user:pass;
	int len=strlen(p);
	GdkColor *color;
	
	if(e)
	{
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
			gdk_cairo_set_source_color(cr,&screen);
			cairo_rectangle(cr,0,0,gdk_screen_width(),gdk_screen_height());
			cairo_fill(cr);
		}
	}
	if(stage==2)
	{
		cairo_destroy(cr);
		return;
	}

	gdk_cairo_set_source_color(cr,&bg);
	cairo_rectangle(cr,rc.x,rc.y,rc.width,rc.height);
	cairo_fill(cr);
	gdk_cairo_set_source_color(cr,&border);
	cairo_set_line_width(cr,1.0);
	cairo_stroke(cr);
	cairo_rectangle(cr,rc.x,rc.y,rc.width,rc.height);
	
	if(message)
	{
		color=&msg;
		p=message;
	}
	else if(stage==0)
	{
		if(len<MAX_VISIBLE_CHARS)
			p=user;
		else
			p=user+len-MAX_VISIBLE_CHARS;
		color=&text;
		if(len==0)
		{
			p="Username";
			color=&hint;
		}
	}
	else if(stage==1)
	{
		char spy[MAX_VISIBLE_CHARS+1];
		p=spy;
		if(len<MAX_VISIBLE_CHARS)
		{
			memset(spy,'*',len);
			p[len]=0;
		}
		else
		{
			memset(spy,'*',MAX_VISIBLE_CHARS);
			p[MAX_VISIBLE_CHARS]=0;
		}
		color=&text;
		if(len==0)
		{
			p="Password";
			color=&hint;
		}
	}
	draw_text(cr,rc.x+3,rc.y+3,p,color);
	cairo_destroy(cr);
}

static void on_key(XEvent *event)
{
	char *p;
	int len;
	KeySym key;
	char ascii;

	if(stage!=0 && stage!=1)
		return;
	message=0;
	XLookupString(&event->xkey, &ascii, 1, &key, 0);
	p=(stage==0)?user:pass;
	len=strlen(p);
	if(key==GDK_Escape)
	{
		user[0]=0;
		pass[0]=0;
		stage=0;
		session_select=-1;
	}
	else if(key==GDK_BackSpace)
	{
		if(len>0)
		{
			p[--len]=0;
		}
	}
	else if(key==GDK_Return)
	{
		if(stage==0 && len==0)
			return;
		stage++;
		if(stage==1)
		{
			if(!strcmp(user,"reboot") || !strcmp(user,"shutdown"))
			{
				stage=2;
			}
		}
	}
	else if(key==GDK_F1)
	{
		LXSESSION *sess;
		if(!sessions)
		{
			sessions=do_scan_xsessions();
			session_select=0;
		}
		else
		{
			session_select++;
			if(session_select>= g_slist_length(sessions))
				session_select=0;
		}
		sess=g_slist_nth_data(sessions,session_select);
		if(sess) message=sess->name;
	}
	else if(key>=0x20 && key<=0x7e)
	{
		if(len<MAX_INPUT_CHARS-1)
		{
			p[len++]=key;
			p[len]=0;
		}
	}
	on_expose(stage==2);
}

int ui_main_one(void)
{
	cairo_t *cr;
	PangoFontDescription *desc;
	char *p;
	int w,h;
	int res=0;
	Display *Dpy=gdk_x11_get_default_xdisplay();
	
	/* init something */
	if(sessions)
		free_xsessions(sessions);
	sessions=0;session_select=0;
	user[0]=0;
	pass[0]=0;
	stage=0;
	p=g_key_file_get_string(config,"input","border",0);
	if(!p) p=g_strdup("#CBCAE6");
	gdk_color_parse(p,&border);
	g_free(p);
	p=g_key_file_get_string(config,"input","bg",0);
	if(!p) p=g_strdup("#ffffff");
	gdk_color_parse(p,&bg);
	g_free(p);
	p=g_key_file_get_string(config,"input","hint",0);
	if(!p) p=g_strdup("#CBCAE6");
	gdk_color_parse(p,&hint);
	g_free(p);
	p=g_key_file_get_string(config,"input","text",0);
	if(!p) p=g_strdup("#000000");
	gdk_color_parse(p,&text);
	g_free(p);
	p=g_key_file_get_string(config,"input","msg",0);
	if(!p) p=g_strdup("#ff0000");
	gdk_color_parse(p,&msg);
	g_free(p);

	/* create the window */
	win=gdk_get_default_root_window();
	
	/* create the font */
	if(layout)
	{
		g_object_unref(layout);
		layout=0;
	}
	cr=gdk_cairo_create(win);
	layout=pango_cairo_create_layout(cr);
	cairo_destroy(cr);	
	p=g_key_file_get_string(config,"input","font",0);
	if(!p) p=g_strdup("Sans 14");
	desc=pango_font_description_from_string(p);
	pango_layout_set_font_description(layout,desc);
	pango_font_description_free(desc);
	g_free(p);

	/* set window size */
	if(layout)
	{
		char temp[MAX_VISIBLE_CHARS+1+1];
		memset(temp,'A',sizeof(temp));
		temp[sizeof(temp)-1]=0;
		get_text_layout(temp,&w,&h);
		rc.width=w+6;rc.height=h+6;
		rc.x=(gdk_screen_width()-rc.width)/2;
		rc.y=(gdk_screen_height()-rc.height)/2;
	}
	
	/* connect key event */
	XSelectInput(Dpy, GDK_WINDOW_XWINDOW(win), ExposureMask | KeyPressMask);
	XGrabKeyboard(Dpy, GDK_WINDOW_XWINDOW(win), False, GrabModeAsync, GrabModeAsync, CurrentTime);
	XMapWindow(Dpy, GDK_WINDOW_XWINDOW(win));

	on_expose(1);

	/* main loop */
	while(stage!=2 || XPending(Dpy))
	{
		XEvent event;
#if 0
		int ret;
		if(!XPending(Dpy))
		{
			struct pollfd pf={.fd=Dpy->fd,.events=POLLIN};
			ret=poll(&pf,1,-1);
			if(ret!=1 || pf.revents!=POLLIN)
			{
				res=-1;
				break;
			}
		}
#endif
		XNextEvent(Dpy,&event);
		switch(event.type){
		case KeyPress:
			on_key(&event);
			break;
		case Expose:
			on_expose(1);
			break;
		default:
			break;
		}
	}
	if(res!=-1)
	{
		XUngrabKeyboard(Dpy,CurrentTime);
		XSelectInput(Dpy,GDK_WINDOW_XWINDOW(win),0);
		XSync(Dpy,0);
	}
	if(layout)
	{
		g_object_unref(layout);
		layout=0;
	}
	message=0;
	return res;
}

int ui_main(void)
{
	while(1)
	{
		int ret=ui_main_one();
		if(ret==0 && stage==2)
		{
			struct passwd *pw;
			int ret;
			if(!strcmp(user,"reboot"))
			{
				do_reboot();
			}
			else if(!strcmp(user,"shutdown"))
			{
				do_shutdown();
			}
			ret=auth_user(user,pass,&pw);
			if(AUTH_SUCCESS==ret && pw!=NULL)
			{
				char *exec=0;
				if(sessions && session_select>0)
				{
					LXSESSION *sess;
					sess=g_slist_nth_data(sessions,session_select);
					exec=g_strdup(sess->exec);
					free_xsessions(sessions);
				}
				sessions=0;session_select=-1;
				do_login(pw,exec);
				g_free(exec);
			}
		}
		else
		{
			break;
		}
	}
	return 0;
}

int ui_show(int b)
{
	return 0;
}

int ui_reset(void)
{
	user[0]=0;
	pass[0]=0;
	stage=0;
	return 0;
}

#if 0
int ui_set_bg(void)
{
	char *bg;
	char *style;
	
	win=gdk_get_default_root_window();
	bg=g_key_file_get_string(config,"display","bg",0);
	if(!bg) bg=g_strdup("#222E45");
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
		gdk_color_parse(bg,&screen);
		//gdk_window_set_background(win,&screen);
	}
	g_free(bg);
	g_free(style);
	return 0;
}
#endif
