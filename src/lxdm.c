#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef HAVE_LIBPAM
#define HAVE_LIBPAM 1
#endif
#ifndef HAVE_LIBXMU
#define HAVE_LIBXMU	1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <glib.h>
#include <gdk/gdk.h>
#include <gdk/gdkx.h>
#include <X11/Xlib.h>

#include <linux/vt.h>

#if HAVE_LIBXMU
#include <X11/Xmu/WinUtil.h>
#endif

#if HAVE_LIBPAM
#include <security/pam_appl.h>
#endif

#if HAVE_LIBCK_CONNECTOR
#include "ck-connector.h"
#endif

#include "lxdm.h"

GKeyFile *config;
static pid_t server;
#if HAVE_LIBPAM
static pam_handle_t *pamh;
#endif
#if HAVE_LIBCK_CONNECTOR
static CkConnector *ckc;
#endif
static Window *my_xid;
static unsigned int my_xid_n;
static char *self;
static pid_t child;
static int reason;
static char mcookie[33];
static int tty=7;

static int get_active_vt (void)
{
	int console_fd;
	struct vt_stat console_state = { 0 };

	console_fd = open ("/dev/tty0", O_RDONLY | O_NOCTTY);

	if (console_fd < 0) {
		goto out;
	}

	if (ioctl (console_fd, VT_GETSTATE, &console_state) < 0) {
		goto out;
	}

out:
  	if (console_fd >= 0) {
    		close (console_fd);
	}

	return console_state.v_active;
}


void lxdm_get_tty(void)
{
	char *s=g_key_file_get_string(config,"server","arg",0);
	int arc;
	char **arg;
	int len;
	int gotvtarg=0;
	int nr=0;
	if(!s) s=g_strdup("/usr/bin/X");
	g_shell_parse_argv(s,&arc,&arg,0);
	g_free(s);
	for(len!=0;arg && arg[len];len++)
	{
		char *p=arg[len];
		if(!strncmp(p,"vt",2) && isdigit(p[2]) && 
				(!p[3] || (isdigit(p[3]) && !p[4])))
		{
			tty=atoi(p+2);
			gotvtarg=1;
			break;
		}
	}
	if(!gotvtarg)
	{
		/* support plymouth */
		nr=g_file_test("/var/spool/gdm/force-display-on-active-vt",G_FILE_TEST_EXISTS);
		if(nr || g_key_file_get_integer(config,"base","active_vt",0))
		{
			/* get active vt dynamic  */
			tty=get_active_vt();
		}
		if(nr) g_unlink("/var/spool/gdm/force-display-on-active-vt");
	}
	arg=g_renew(char *,arg,len+10);
	if(!gotvtarg)
		arg[len++]=g_strdup_printf("vt%d",tty);
	arg[len++]=g_strdup("-nolisten");
	arg[len++]=g_strdup("tcp");
	if(nr!=0)
		arg[len++]=g_strdup("-nr");
	arg[len]=NULL;
	s=g_strjoinv(" ",arg);
	g_strfreev(arg);
	g_key_file_set_string(config,"server","arg",s);
	g_free(s);
}

void lxdm_restart_self(void)
{
	reason=0;
	exit(0);
}

void lxdm_quit_self(void)
{
	reason=1;
	exit(0);
}

void log_print(char *fmt,...)
{
	static FILE *log;
	va_list ap;
	if(!fmt)
	{
		if(log)
			fclose(log);
		log=0;
		return;
	}
	if(!log)
	{
		log=fopen("/var/log/lxdm.log","w");
		if(!log)
			return;
	}
	va_start(ap,fmt);
	vfprintf(log,fmt,ap);
	va_end(ap);
	fflush(log);
}

GSList *do_scan_xsessions(void)
{
	GSList *l=NULL;
	GDir *d;
	LXSESSION *sess;
	char *name;
	
	d=g_dir_open("/usr/share/xsessions",0,NULL);
	if(!d) return NULL;
	while((name=(char*)g_dir_read_name(d))!=NULL)
	{
		GKeyFile *f=g_key_file_new();
		char *tmp=g_strdup_printf("/usr/share/xsessions/%s",name);
		gboolean ret=g_key_file_load_from_file(f,tmp,G_KEY_FILE_NONE,NULL);
		while(ret==TRUE)
		{
			char *name=g_key_file_get_string(f,"Desktop Entry","Name",0);
			if(!name) break;
			char *exec=g_key_file_get_string(f,"Desktop Entry","Exec",0);
			if(!exec)
			{
				g_free(name);
				break;
			}
			sess=g_malloc(sizeof(LXSESSION));
			sess->name=name;
			sess->exec=exec;
			if(!strcmp(name,"LXDE"))
				l=g_slist_prepend(l,sess);
			else
				l=g_slist_append(l,sess);
			break;
		}
		g_key_file_free(f);
	}
	g_dir_close(d);
	return l;
}

void free_xsessions(GSList *l)
{
	GSList *p;
	LXSESSION *sess;
	
	for(p=l;p;p=p->next)
	{
		sess=p->data;
		g_free(sess->name);
		g_free(sess->exec);
		g_free(sess);
	}
	g_slist_free(l);
}

void create_server_auth(void)
{
#if 0
	GRand *h;
	const char *digits = "0123456789abcdef";
	int i,r,hex=0;
	char *authfile;
	char *tmp;
	
	h=g_rand_new();
	for(i=0;i<31;i++)
	{
		r=g_rand_int(h)%16;
		mcookie[i] = digits[r];
		if (r>9)
			hex++;
	}
	if ((hex%2) == 0)
		r = g_rand_int(h)%10;
	else
		r = g_rand_int(h)%5+10;
	mcookie[31] = digits[r];
	mcookie[32]=0;
	g_rand_free(h);
	
	authfile=g_key_file_get_string(config,"base","authfile",0);
	if(!authfile)
		authfile=g_strdup("/var/run/lxdm.auth");
	tmp=g_strdup_printf("XAUTHORITY=%s",authfile);
	putenv(tmp);
	g_free(tmp);
	remove(authfile);
	tmp=g_strdup_printf("xauth -q -f %s add %s . %s",
			authfile,getenv("DISPLAY"),mcookie);
	system(tmp);
	g_free(tmp);
	g_free(authfile);
#endif
}

void create_client_auth(char *home)
{
#if 0
	char *tmp;
	char *authfile;
	
	tmp=g_strdup_printf("%s/.Xauthority",getenv("HOME"));
	remove(tmp);
	g_free(tmp);
	tmp=g_strdup_printf("xauth -q add %s . %s",
			getenv("DISPLAY"),mcookie);
	system(tmp);
	g_free(authfile);
	g_free(tmp);
#endif
}

int lxdm_auth_user(char *user,char *pass,struct passwd **ppw)
{
	struct passwd *pw;
	struct spwd *sp;
	char *real;
	char *enc;
	if(!user)
		return AUTH_ERROR;
	if(!user[0])
		return AUTH_BAD_USER;
	pw=getpwnam(user);
	endpwent();
	if(!pw)
		return AUTH_BAD_USER;
	if(!pass)
	{
		*ppw=pw;
		return AUTH_SUCCESS;
	}
	sp=getspnam(user);
	if(!sp)
	{
		return AUTH_FAIL;
	}
	endspent();
	real=sp->sp_pwdp;
	if(!real || !real[0])
	{
		if(!pass[0])
		{
			*ppw=pw;
			return AUTH_SUCCESS;
		}
		else
		{
			return AUTH_FAIL;
		}
	}
	enc=crypt(pass,real);
	if(strcmp(real,enc))
		return AUTH_FAIL;
	if(strstr(pw->pw_shell,"nologin"))
		return AUTH_PRIV;
	*ppw=pw;
	return AUTH_SUCCESS;
}

void switch_user(struct passwd *pw,char *run,char **env)
{
	if(!pw || initgroups(pw->pw_name, pw->pw_gid) ||
		setgid(pw->pw_gid) || setuid(pw->pw_uid) || setsid()==-1)
	{
		exit(EXIT_FAILURE);
	}
	chdir(pw->pw_dir);
	create_client_auth(pw->pw_dir);
	execle("/etc/lxdm/Xsession","/etc/lxdm/Xsession",run,NULL,env);
	exit(EXIT_FAILURE);
}

void get_lock(void)
{
	FILE *fp;
	char *lockfile;
	
	lockfile=g_key_file_get_string(config,"base","lock",0);
	if(!lockfile) lockfile=g_strdup("/var/run/lxdm.pid");
	
	fp=fopen(lockfile,"r");
	if(fp)
	{
		int pid;
		int ret;
		ret=fscanf(fp,"%d",&pid);
		fclose(fp);
		if(ret==1)
		{
			if(kill(pid,0)==0 || (ret==-1 && errno==EPERM))
			{
				exit(EXIT_SUCCESS);
			}
		}
	}
	fp=fopen(lockfile,"w");
	if(!fp)
		exit(EXIT_FAILURE);
	fprintf(fp,"%d",getpid());
	fclose(fp);
	g_free(lockfile);
}

void put_lock(void)
{
	FILE *fp;
	char *lockfile;
	
	lockfile=g_key_file_get_string(config,"base","lock",0);
	if(!lockfile) lockfile=g_strdup("/var/run/lxdm.pid");
	fp=fopen(lockfile,"r");
	if(fp)
	{
		int pid;
		int ret;
		ret=fscanf(fp,"%d",&pid);
		fclose(fp);
		if(ret==1 && pid==getpid())
			remove(lockfile);
	}
	g_free(lockfile);
}

void stop_pid(int pid)
{
	if(pid<=0) return;
	if(killpg(pid,SIGTERM)<0)
		killpg(pid,SIGKILL);
	if(kill(pid,0)==0)
	{
		if(kill(pid,SIGTERM))
			kill(pid,SIGKILL);
		while(1)
		{
			int wpid,status;
			wpid=wait(&status);
			if(pid==wpid) break;
		}
	}
	while(waitpid(-1,0,WNOHANG)>0);
}

static void on_xserver_stop(GPid pid,gint status,gpointer data)
{
	stop_pid(server);
	server=-1;
	lxdm_restart_self();
}

void startx(void)
{
	char *arg;
	char **args;
	
	if(!getenv("DISPLAY"))
		putenv("DISPLAY=:0");
		
	create_server_auth();
		
	arg=g_key_file_get_string(config,"server","arg",0);
	if(!arg) arg=g_strdup("/usr/bin/X");
	args=g_strsplit(arg," ",-1);
	g_free(arg);
	
	server=vfork();
	
	switch(server){
	case 0:
		setpgid(0,getpid());
		execvp(args[0], args);
		break;
	case -1:
		exit(EXIT_FAILURE);
		break;
	default:
		break;
	}
	g_strfreev(args);
	g_child_watch_add(server,on_xserver_stop,0);
}

void exit_cb(void)
{
	if(child>0)
	{
		killpg(child,SIGHUP);
		stop_pid(child);
		child=-1;
	}
#if HAVE_LIBPAM
	if(pamh) pam_end(pamh,PAM_SUCCESS);
#endif
	if(server>0)
	{
		stop_pid(server);
		server=-1;
	}
	put_lock();
	if(reason==0)
	{
		execlp(self,self,NULL);
	}
}

int CatchErrors(Display *dpy, XErrorEvent *ev)
{
    return 0;
}

void get_my_xid(void)
{
	Window dummy,parent;
	Display *Dpy=gdk_x11_get_default_xdisplay();
	Window Root=gdk_x11_get_default_root_xwindow();
	XQueryTree(Dpy, Root, &dummy, &parent, &my_xid, &my_xid_n);
}

int is_my_id(XID id)
{
	int i;
	if(!my_xid)
		return 0;
	for(i=0;i<my_xid_n;i++)
		if(id==my_xid[i]) return 1;
	return 0;
}

void free_my_xid(void)
{
	XFree(my_xid);
	my_xid=0;
}

void stop_clients(int top)
{
	Window dummy,parent;
	Window *children;
 	unsigned int nchildren;
	unsigned int i;
	XWindowAttributes attr;
	Display *Dpy=gdk_x11_get_default_xdisplay();
	Window Root=gdk_x11_get_default_root_xwindow();

	XSync(Dpy, 0);
	XSetErrorHandler(CatchErrors);

	nchildren = 0;
	XQueryTree(Dpy, Root, &dummy, &parent, &children, &nchildren);
 	if(!top)
	{
		for(i=0; i<nchildren; i++)
		{
			if(XGetWindowAttributes(Dpy, children[i], &attr) && (attr.map_state == IsViewable))
#if HAVE_LIBXMU
				children[i] = XmuClientWindow(Dpy, children[i]);
#else
				children[i]=children[i];
#endif
			else
 				children[i] = 0;
		}
	}

	for(i=0; i<nchildren; i++)
	{
		if(children[i] && !is_my_id(children[i]))
		{
			XKillClient(Dpy, children[i]);
			//printf("kill %d\n",i);
		}
	}
	XFree((char *)children);
	XSync(Dpy, 0);
	XSetErrorHandler(NULL);
}

static void on_session_stop(GPid pid,gint status,gpointer data)
{
	int code=WEXITSTATUS(status);

	killpg(pid,SIGHUP);
	stop_pid(pid);
	child=-1;

	if(server>0)
	{
		/* FIXME just work around lxde bug of focus can't set */
		//stop_clients(0);
		stop_clients(1);
		free_my_xid();
	}
#if HAVE_LIBPAM
	if(pamh)
	{
		pam_close_session(pamh,0);
		pam_setcred(pamh, PAM_DELETE_CRED);
	}
#endif
#if HAVE_LIBCK_CONNECTOR
	if(ckc!=NULL)
	{
		DBusError error;
		dbus_error_init (&error);
		ck_connector_close_session(ckc, &error);
		unsetenv("XDG_SESSION_COOKIE");
	}
#endif
	if(code==0)
	{
		/* xterm will quit use this, but we shul not quit here */
		/* so wait someone to kill me may better */
		//lxdm_quit_self();
		sleep(2);
	}
	
	ui_prepare();
}

void lxdm_do_login(struct passwd *pw,char *session,char *lang)
{
	int pid;
	
	if (pw->pw_shell[0] == '\0')
	{
		setusershell();
		strcpy(pw->pw_shell, getusershell());
		endusershell();
	}
#if HAVE_LIBPAM
	if(pamh)
	{
		int err;
		pam_set_item(pamh, PAM_USER, pw->pw_name);
		pam_authenticate(pamh, 0);
		pam_acct_mgmt(pamh, PAM_SILENT);
		pam_setcred(pamh, PAM_ESTABLISH_CRED);
		err=pam_open_session(pamh,0); /* FIXME pam session failed */
		if(err!=PAM_SUCCESS)
		{
			//printf("%s\n",pam_strerror(pamh,err));
		}
	}
#endif
#if HAVE_LIBCK_CONNECTOR
	if(ckc!=NULL)
	{
		DBusError error;
		char x[256],*d,*n;
		sprintf(x,"/dev/tty%d",tty);
		dbus_error_init (&error);
		d=x;n=getenv("DISPLAY");
		if(ck_connector_open_session_with_parameters(ckc,&error,
				"unix-user",&pw->pw_uid,
				"display-device",&d,
				"x11-display-device",&d,
				"x11-display",&n,
				NULL))
		{
			setenv("XDG_SESSION_COOKIE",ck_connector_get_cookie(ckc),1);
		}
	}
#endif
	get_my_xid();
	child = pid = fork();
	if(child==0)
	{
		char *env[10];
		char *path;
		int i=0;

#if HAVE_LIBPAM
		if(pamh)
			pam_end(pamh,PAM_SUCCESS);
#endif

		env[i++]=g_strdup_printf("TERM=%s",getenv("TERM"));
		env[i++]=g_strdup_printf("HOME=%s", pw->pw_dir);
		env[i++]=g_strdup_printf("SHELL=%s", pw->pw_shell);
		env[i++]=g_strdup_printf("USER=%s", pw->pw_name);
		env[i++]=g_strdup_printf("LOGNAME=%s", pw->pw_name);
		env[i++]=g_strdup_printf("DISPLAY=%s", getenv("DISPLAY"));
		path=g_key_file_get_string(config,"base","path",0);
		if(path) env[i++]=path;
		g_free(path);
		if(lang && lang[0])
			env[i++]=g_strdup_printf("LANG=%s",lang);
		if(getenv("XDG_SESSION_COOKIE"))
			env[i++]=g_strdup_printf("XDG_SESSION_COOKIE=%s",getenv("XDG_SESSION_COOKIE"));
		env[i++]=0;

		if(session && session[0])
			session=g_strdup(session);
		else
			session=0;
		if(!session)
			session=g_key_file_get_string(config,"base","session",0);
		if(!session && getenv("PREFERRED"))
			session=g_strdup(getenv("PREFERRED"));
		if(!session && getenv("DESKTOP"))
		{
			char *p=getenv("DESKTOP");
			if(!strcmp(p,"LXDE"))
				session=g_strdup("/usr/bin/startlxde");
			else if(!strcmp(p,"GNOME"))
				session=g_strdup("/usr/bin/gnome-session");
			else if(!strcmp(p,"KDE"))
				session=g_strdup("/usr/bin/startkde");
			else if(!strcmp(p,"XFCE"))
				session=g_strdup("startxfce4");
		}
		if(!session)
			session=g_strdup("");

		switch_user(pw,session,env);
		reason=4;
		exit(EXIT_FAILURE);
	}
	g_child_watch_add(pid,on_session_stop,0);
}

void lxdm_do_reboot(void)
{
	char *cmd;	
	cmd=g_key_file_get_string(config,"cmd","reboot",0);
	if(!cmd) cmd=g_strdup("reboot");
	reason=1;
	system(cmd);
	g_free(cmd);
	lxdm_quit_self();
}

void lxdm_do_shutdown(void)
{
	char *cmd;	
	cmd=g_key_file_get_string(config,"cmd","shutdown",0);
	if(!cmd) cmd=g_strdup("shutdown -h now");
	reason=1;
	system(cmd);
	g_free(cmd);
	lxdm_quit_self();
}

int lxdm_cur_session(void)
{
	return child;
}

int lxdm_do_auto_login(void)
{
	struct passwd *pw;
	char *user;
	
	user=g_key_file_get_string(config,"base","autologin",0);
	if(!user)
		return 0;
	if(AUTH_SUCCESS!=lxdm_auth_user(user,0,&pw))
		return 0;
	lxdm_do_login(pw,0,0);
	return 1;
}

void sig_handler(int sig)
{
	log_print("catch signal %d\n",sig);
	switch(sig){
	case SIGTERM:
	case SIGINT:
		lxdm_quit_self();
		break;
	default:
		break;
	}
}

void set_signal(void)
{
	signal(SIGQUIT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGKILL, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGHUP, sig_handler);
	signal(SIGPIPE, sig_handler);
	signal(SIGUSR1, sig_handler);
	signal(SIGALRM, sig_handler);
}

#if HAVE_LIBPAM
int conv_cb(int num_msg, const struct pam_message **msg,
         struct pam_response **resp, void *appdata_ptr)
{
	return PAM_SUCCESS;
}

void init_pam(void)
{
	struct pam_conv conv;
	char x[256];
	conv.conv=conv_cb;
	if(PAM_SUCCESS!=pam_start("lxdm",NULL,&conv,&pamh))
	{
		pamh=NULL;
		return;
	}
	sprintf(x,"tty%d",tty);
	pam_set_item(pamh,PAM_TTY,x);
	pam_set_item(pamh,PAM_XDISPLAY,getenv("DISPLAY"));
	pam_set_item(pamh,PAM_RHOST,"localhost");
	pam_set_item(pamh,PAM_RUSER,"root");
}
#endif

#if HAVE_LIBCK_CONNECTOR
void init_ck(void)
{
	ckc=ck_connector_new();
}
#endif

int main(int arc,char *arg[])
{
	int tmp;
	int daemonmode=0;

	if(getuid()!=0)
	{
		printf("only root allow to use this program\n");
		exit(EXIT_FAILURE);
	}

	while((tmp=getopt(arc,arg,"hd"))!=EOF)
	{
		switch(tmp){
		case 'd':
			daemonmode=1;
			break;
		case 'h':
			printf("usage:  lxdm [options ...]\n");
			printf("options:\n");
			printf("    -d: daemon mode\n");
			exit(EXIT_SUCCESS);
			break;
		}
	}
	
	if(daemonmode)
		daemon(1,1);
		
	self=arg[0];

	config=g_key_file_new();
	g_key_file_load_from_file(config,"/etc/lxdm/lxdm.conf",G_KEY_FILE_NONE,NULL);

	get_lock();
	atexit(exit_cb);
	
	set_signal();
	lxdm_get_tty();
	startx();

	for(tmp=0;tmp<200;tmp++)
	{
		if(gdk_init_check(0,0))
			break;
		usleep(50*1000);
	}
	if(tmp>=200)
		exit(EXIT_FAILURE);

#if HAVE_LIBPAM		
	init_pam();
#endif
#if HAVE_LIBCK_CONNECTOR
	init_ck();
#endif

	lxdm_do_auto_login();

	ui_main();

	lxdm_restart_self();

	return 0;
}
