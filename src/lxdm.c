#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <X11/Xlib.h>
#include <X11/Xmu/WinUtil.h>
#include <security/pam_appl.h>

#include "lxdm.h"

GKeyFile *config;
static pid_t server;
static pam_handle_t *pamh;
static Window *my_xid;
static unsigned int my_xid_n;
static char *self;
static pid_t child;
static int reason;

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

int auth_user(char *user,char *pass,struct passwd **ppw)
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
		setgid(pw->pw_gid) || setuid(pw->pw_uid) || setpgrp())
	{
		exit(EXIT_FAILURE);
	}
	chdir(pw->pw_dir);
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

void startx(void)
{
	char *arg;
	char **args;
	
	if(!getenv("DISPLAY"))
		putenv("DISPLAY=:0");
	
	server=vfork();
	
	arg=g_key_file_get_string(config,"server","arg",0);
	if(!arg) arg=g_strdup("X");
	args=g_strsplit(arg," ",-1);
	g_free(arg);
	
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

void stopx(void)
{
	stop_pid(server);
	server=-1;
}

void exit_cb(void)
{
	if(child>0)
	{
		killpg(child,SIGHUP);
		stop_pid(child);
		child=-1;
	}
	if(pamh) pam_end(pamh,PAM_SUCCESS);
	stopx();
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
				children[i] = XmuClientWindow(Dpy, children[i]);
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

void do_login(struct passwd *pw,char *session)
{
	int pid;
	int status;
	
	if (pw->pw_shell[0] == '\0')
	{
		setusershell();
		strcpy(pw->pw_shell, getusershell());
		endusershell();
	}
	if(pamh)
	{
		int err;
		pam_setcred(pamh, PAM_ESTABLISH_CRED);
		err=pam_open_session(pamh,0);
		if(err!=PAM_SUCCESS)
		{
			//printf("%s\n",pam_strerror(pamh,err));
		}
	}
	
	get_my_xid();

	child = pid = fork();
	if(child==0)
	{
		char *env[10];
		char *path;
		int i=0;
		
		if(pamh)
			pam_end(pamh,PAM_SUCCESS);
		
		env[i++]=g_strdup_printf("TERM=%s",getenv("TERM"));
		env[i++]=g_strdup_printf("HOME=%s", pw->pw_dir);
		env[i++]=g_strdup_printf("SHELL=%s", pw->pw_shell);
		env[i++]=g_strdup_printf("USER=%s", pw->pw_name);
		env[i++]=g_strdup_printf("LOGNAME=%s", pw->pw_name);
		env[i++]=g_strdup_printf("DISPLAY=%s", getenv("DISPLAY"));
		path=g_key_file_get_string(config,"base","path",0);
		if(path) env[i++]=path;
		g_free(path);
		env[i++]=0;
		if(session) session=g_strdup(session);
		if(!session)
			session=g_key_file_get_string(config,"base","session",0);
		if(!session) session=g_strdup("startlxde");

		switch_user(pw,session,env);
		reason=4;
		exit(EXIT_FAILURE);
	}
	while(1)
	{
		int wpid = wait(&status);
		if(wpid==server)
		{
			stopx();
			break;
		}
		else if(wpid==child)
		{
			child=-1;
			break;
		}
	}
	if(server>0)
	{
		stop_clients(0);
		stop_clients(1);
		free_my_xid();
	}

	killpg(pid,SIGHUP);
	stop_pid(pid);
	child=-1;
	if(pamh)
	{
		pam_close_session(pamh,0);
		pam_setcred(pamh, PAM_DELETE_CRED);
	}
	if(server==-1)
	{
		exit(0);
	}
}

void do_reboot(void)
{
	char *cmd;	
	cmd=g_key_file_get_string(config,"cmd","reboot",0);
	if(!cmd) cmd=g_strdup("reboot");
	reason=2;
	system(cmd);
	g_free(cmd);
	exit(0);
}

void do_shutdown(void)
{
	char *cmd;	
	cmd=g_key_file_get_string(config,"cmd","shutdown",0);
	if(!cmd) cmd=g_strdup("shutdown -h now");
	reason=3;
	system(cmd);
	g_free(cmd);
	exit(0);
}

int do_auto_login(void)
{
	struct passwd *pw;
	char *user;
	
	user=g_key_file_get_string(config,"base","autologin",0);
	if(!user)
		return 0;
	if(AUTH_SUCCESS!=auth_user(user,0,&pw))
		return 0;
	do_login(pw,0);
	return 1;
}

void sig_handler(int sig)
{
	switch(sig){
	case SIGTERM:
	case SIGINT:
	case SIGPIPE:
		reason=1;
		exit(0);
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

int conv_cb(int num_msg, const struct pam_message **msg,
         struct pam_response **resp, void *appdata_ptr)
{
	return PAM_SUCCESS;
}

void init_pam(void)
{
	struct pam_conv conv;
	conv.conv=conv_cb;
	if(PAM_SUCCESS!=pam_start("lxdm",NULL,&conv,&pamh))
	{
		pamh=NULL;
		return;
	}
	pam_set_item(pamh,PAM_TTY,getenv("DISPLAY"));
	pam_set_item(pamh,PAM_RHOST,"localhost");
	pam_set_item(pamh,PAM_RUSER,"root");
}

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

	startx();

	for(tmp=0;tmp<200;tmp++)
	{
		if(gdk_init_check(0,0))
			break;
		usleep(50*1000);
	}
	if(tmp==100)
		exit(EXIT_FAILURE);
		
	init_pam();

	ui_set_bg();
	do_auto_login();

	ui_main();

	return 0;
}

