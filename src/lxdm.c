/*
 *      lxdm.c - main entry of lxdm
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

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef HAVE_LIBPAM
#define HAVE_LIBPAM 0
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>
#include <ctype.h>
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
#include <X11/Xlib.h>
#include <X11/XKBlib.h>

#include <sys/vt.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <execinfo.h>

#include <utmp.h>

#if HAVE_LIBPAM
#include <security/pam_appl.h>
#endif

#if HAVE_LIBCK_CONNECTOR
#include <ck-connector.h>
#endif

#if HAVE_LIBXAU
#include <X11/Xauth.h>
#include <sys/utsname.h>
#endif

#include "lxdm.h"
#include "lxcom.h"

GKeyFile *config;
static pid_t server;
#if HAVE_LIBCK_CONNECTOR
static CkConnector *ckc;
#endif
static pid_t child;
static int old_tty=1,tty = 7;

#ifndef DISABLE_XAUTH
static char mcookie[33];
#endif

#if HAVE_LIBXAU
static Xauth x_auth;
#endif

static int get_active_vt(void)
{
	int console_fd;
	struct vt_stat console_state = { 0 };

	console_fd = open("/dev/console", O_RDONLY | O_NOCTTY);

	if( console_fd < 0 )
		goto out;

	if( ioctl(console_fd, VT_GETSTATE, &console_state) < 0 )
		goto out;

out:
	if( console_fd >= 0 )
		close(console_fd);

	return console_state.v_active;
}

static void set_active_vt(int vt)
{
	int fd;

	fd = open("/dev/console", O_RDWR);
	if( fd < 0 )
		fd = 0;
	ioctl(fd, VT_ACTIVATE, vt);
	if( fd != 0 )
		close(fd);
}

static gboolean plymouth_is_running(void)
{
	int status;
	gboolean res;

	res=g_spawn_command_line_sync ("/bin/plymouth --ping",NULL,NULL,&status,NULL);
	if(!res) return FALSE;
	return WIFEXITED (status) && WEXITSTATUS (status) == 0;
}

static void plymouth_quit_with_transition(void)
{
	g_spawn_command_line_sync("/bin/plymouth quit --retain-splash",NULL,NULL,NULL,NULL);
}

static void plymouth_quit_without_transition(void)
{
	g_spawn_command_line_sync("/bin/plymouth quit --retain-splash",NULL,NULL,NULL,NULL);
}

static void plymouth_prepare_transition(void)
{
	g_spawn_command_line_sync ("/bin/plymouth deactivate",NULL,NULL,NULL,NULL);
}

void lxdm_get_tty(void)
{
    char *s = g_key_file_get_string(config, "server", "arg", 0);
    int arc;
    char **arg;
    int len;
    int gotvtarg = 0;
    int nr = 0;
    gboolean plymouth;
    
    plymouth=plymouth_is_running();
    if(plymouth) plymouth_prepare_transition();

    old_tty=get_active_vt();
    if( !s ) s = g_strdup("/usr/bin/X");
    g_shell_parse_argv(s, &arc, &arg, 0);
    g_free(s);
    for( len = 0; arg && arg[len]; len++ )
    {
        char *p = arg[len];
        if( !strncmp(p, "vt", 2) && isdigit(p[2]) &&
           ( !p[3] || (isdigit(p[3]) && !p[4]) ) )
        {
            tty = atoi(p + 2);
            gotvtarg = 1;
        }
    }
    if(!gotvtarg)
    {
        /* support plymouth */
        nr = g_file_test("/var/spool/gdm/force-display-on-active-vt", G_FILE_TEST_EXISTS);
        if( nr || g_key_file_get_integer(config, "server", "active_vt", 0) )
            /* use the active vt */
            tty = old_tty;
        if( nr ) unlink("/var/spool/gdm/force-display-on-active-vt");
        if(plymouth)
        {
			nr=1;
			plymouth_quit_with_transition();
		}
    }
    else
    {
		if(plymouth) /* set tty and plymouth running */
			plymouth_quit_without_transition();
	}
    arg = g_renew(char *, arg, len + 10);
    if( !gotvtarg )
        arg[len++] = g_strdup_printf("vt%d", tty);
    arg[len++] = g_strdup("-nolisten");
    arg[len++] = g_strdup("tcp");
    if( nr != 0 )
        arg[len++] = g_strdup("-nr");
    arg[len] = NULL;
    s = g_strjoinv(" ", arg);
    g_strfreev(arg);
    g_key_file_set_string(config, "server", "arg", s);
    g_free(s);
    if(old_tty!=tty)
        set_active_vt(tty);
}

void lxdm_quit_self(int code)
{
	exit(code);
}

void log_print(char *fmt, ...)
{
	FILE *log;
	va_list ap;
	log = fopen("/var/log/lxdm.log", "a");
	if(!log) return;
	va_start(ap, fmt);
	vfprintf(log, fmt, ap);
	va_end(ap);
	fclose(log);
}

#ifdef LXDM_DEBUG
#define dbg_printf log_print
#else
#define dbg_printf(fmt,...)
#endif

GSList *do_scan_xsessions(void)
{
    GSList *xsessions = NULL;
    GDir *d;
    const char *basename;
    GKeyFile *f;

    d = g_dir_open(XSESSIONS_DIR, 0, NULL);
    if( !d )
        return NULL;

    f = g_key_file_new();
    while( ( basename = g_dir_read_name(d) ) != NULL )
    {
        char *file_path;
        gboolean loaded;

        if(!g_str_has_suffix(basename, ".desktop"))
            continue;

        file_path = g_build_filename(XSESSIONS_DIR, basename, NULL);
        loaded = g_key_file_load_from_file(f, file_path, G_KEY_FILE_NONE, NULL);
        g_free(file_path);

        if( loaded )
        {
            char *name = g_key_file_get_locale_string(f, "Desktop Entry", "Name", NULL, NULL);
            if( name )
            {
                char *exec = g_key_file_get_string(f, "Desktop Entry", "Exec", NULL);
                if(exec)
                {
                    Session* sess = g_new( Session, 1 );
                    sess->name = name;
                    sess->exec = exec;
                    sess->desktop_file = g_strdup(basename);
                    if( !strcmp(name, "LXDE") )
                        xsessions = g_slist_prepend(xsessions, sess);
                    else
                        xsessions = g_slist_append(xsessions, sess);
                    continue; /* load next file */
                    g_free(exec);
                }
                g_free(name);
            }
        }
    }
    g_dir_close(d);
    g_key_file_free(f);
    return xsessions;
}

void free_xsessions(GSList *l)
{
    GSList *p;
    Session *sess;

    for( p = l; p; p = p->next )
    {
        sess = p->data;
        g_free(sess->name);
        g_free(sess->exec);
        g_free(sess);
    }
    g_slist_free(l);
}

static void replace_env(char** env, const char* name, const char* new_val)
{
    register char** penv;
    for(penv = env; *penv; ++penv)
    {
        if(g_str_has_prefix(*penv, name))
        {
            g_free(*penv);
            *penv = g_strconcat(name, new_val, NULL);
            return;
        }
    }
    *penv = g_strconcat(name, new_val, NULL);
    *(penv + 1) = NULL;
}

#ifndef DISABLE_XAUTH
void create_server_auth(void)
{
    GRand *h;
    int i;
    char *authfile;

    h = g_rand_new();
#if HAVE_LIBXAU
    for (i=0;i<16;i++)
        mcookie[i]=(char)g_rand_int(h);
#else
    const char *digits = "0123456789abcdef";
    int r,hex=0;
    for( i = 0; i < 31; i++ )
    {
        r = g_rand_int(h) % 16;
        mcookie[i] = digits[r];
        if( r > 9 )
            hex++;
    }
    if( (hex % 2) == 0 )
        r = g_rand_int(h) % 10;
    else
        r = g_rand_int(h) % 5 + 10;
    mcookie[31] = digits[r];
    mcookie[32] = 0;
#endif
    g_rand_free(h);

    authfile = g_key_file_get_string(config, "base", "authfile", 0);
    if(!authfile)
    {
        mkdir("/var/run/lxdm",0700);
        authfile = g_strdup("/var/run/lxdm/lxdm.auth");
    }
    setenv("XAUTHORITY",authfile,1);
    remove(authfile);
#if HAVE_LIBXAU
    FILE *fp=fopen(authfile,"wb");
    if(fp)
    {
        static char xau_address[80];
        static char xau_number[16];
        static char xau_name[]="MIT-MAGIC-COOKIE-1";
        struct utsname uts;
        uname(&uts);
        sprintf(xau_address, "%s", uts.nodename);
        strcpy(xau_number,getenv("DISPLAY")+1); // DISPLAY always exist at lxdm
        x_auth.family = FamilyLocal;
        x_auth.address = xau_address;
        x_auth.number = xau_number;
        x_auth.name = xau_name;
        x_auth.address_length = strlen(xau_address);
        x_auth.number_length = strlen(xau_number);
        x_auth.name_length = strlen(xau_name);
        x_auth.data = mcookie;
        x_auth.data_length = 16;
        XauWriteAuth(fp,&x_auth);
        fclose(fp);
    }
#else
    char *tmp = g_strdup_printf("xauth -q -f %s add %s . %s",
                          authfile, getenv("DISPLAY"), mcookie);
    system(tmp);
    g_free(tmp);

#endif
    g_free(authfile);
}

void create_client_auth(char *home,char **env)
{
    char *authfile;

    if( getuid() == 0 ) /* root don't need it */
        return;

    authfile = g_strdup_printf("%s/.Xauthority", home);
    remove(authfile);
#if HAVE_LIBXAU
    FILE *fp=fopen(authfile,"wb");
    if(fp)
    {
        XauWriteAuth(fp,&x_auth);
        fclose(fp);
    }
#else
    char *tmp = g_strdup_printf("xauth -q -f %s add %s . %s",
                          authfile, getenv("DISPLAY"), mcookie);
    system(tmp);
    g_free(tmp);
#endif
    replace_env(env,"XAUTHORITY=",authfile);
    g_free(authfile);
}
#endif

#if HAVE_LIBPAM
static char *user_pass[2];

static int do_conv(int num, const struct pam_message **msg,struct pam_response **resp, void *arg)
{
	int result = PAM_SUCCESS;
	int i;
	*resp = (struct pam_response *) calloc(num, sizeof(struct pam_response));
	for(i=0;i<num;i++)
	{
		//printf("MSG: %d %s\n",msg[i]->msg_style,msg[i]->msg);
		switch(msg[i]->msg_style){
		case PAM_PROMPT_ECHO_ON:
			resp[i]->resp=strdup(user_pass[0]?user_pass[0]:"");
			break;
		case PAM_PROMPT_ECHO_OFF:
			resp[i]->resp=strdup(user_pass[1]?user_pass[1]:"");
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			//printf("PAM: %s\n",msg[i]->msg);
			break;
		default:
			break;
		}
	}
	return result;
}

static pam_handle_t *pamh;
static struct pam_conv conv={.conv=do_conv,.appdata_ptr=user_pass};
#endif

int lxdm_auth_user(char *user, char *pass, struct passwd **ppw)
{
    struct passwd *pw;
#if !HAVE_LIBPAM
    struct spwd *sp;
    char *real;
    char *enc;
#endif
    if( !user )
    {
        dbg_printf("user==NULL\n");
        return AUTH_ERROR;
    }
    if( !user[0] )
    {
        dbg_printf("user[0]==0\n");
        return AUTH_BAD_USER;
    }
    pw = getpwnam(user);
    endpwent();
    if( !pw )
    {
        dbg_printf("user %s not found\n",user);
        return AUTH_BAD_USER;
    }
    if( !pass )
    {
        *ppw = pw;
        dbg_printf("user %s auth ok\n",user);
        return AUTH_SUCCESS;
    }
    if(strstr(pw->pw_shell, "nologin"))
    {
        dbg_printf("user %s have nologin shell\n");
        return AUTH_PRIV;
    }
#if !HAVE_LIBPAM
    sp = getspnam(user);
    if( !sp )
        return AUTH_FAIL;
    endspent();
    real = sp->sp_pwdp;
    if( !real || !real[0] )
    {
        if( !pass[0] )
        {
            *ppw = pw;
            dbg_printf("user %s auth with no password ok\n",user);
            return AUTH_SUCCESS;
        }
        else
        {
            dbg_printf("user %s password not match\n");
            return AUTH_FAIL;
        }
    }
    enc = crypt(pass, real);
    if( strcmp(real, enc) )
    {
        dbg_printf("user %s password not match\n");
        return AUTH_FAIL;
    }
#else
    if(pamh) pam_end(pamh,0);
    if(PAM_SUCCESS != pam_start("lxdm", pw->pw_name, &conv, &pamh))
    {
        pamh=NULL;
        dbg_printf("user %s start pam fail\n",user);
        return AUTH_FAIL;
    }
    else
    {
	int ret;
        user_pass[0]=user;user_pass[1]=pass;
        ret=pam_authenticate(pamh,PAM_SILENT);
	user_pass[0]=0;user_pass[1]=0;
	if(ret!=PAM_SUCCESS)
        {
            dbg_printf("user %s auth fail with %d\n",user,ret);
            return AUTH_FAIL;
        }
	//ret=pam_setcred(pamh, PAM_ESTABLISH_CRED);
    }
#endif
    *ppw = pw;
    dbg_printf("user %s auth ok\n",pw->pw_name);
    return AUTH_SUCCESS;
}

#if HAVE_LIBPAM
void setup_pam_session(struct passwd *pw,char *session_name)
{
    int err;
    char x[256];
 
    if(!pamh && PAM_SUCCESS != pam_start("lxdm", pw->pw_name, &conv, &pamh))
    {
        pamh = NULL;
        return;
    }
    if(!pamh) return;
    sprintf(x, "tty%d", tty);
    pam_set_item(pamh, PAM_TTY, x);
#ifdef PAM_XDISPLAY
    pam_set_item( pamh, PAM_XDISPLAY, getenv("DISPLAY") );
#endif

    if(session_name && session_name[0])
    {
        char *env;
        env = g_strdup_printf ("DESKTOP_SESSION=%s", session_name);
        pam_putenv (pamh, env);
        g_free (env);
    }
    err = pam_open_session(pamh, 0); /* FIXME pam session failed */
    if( err != PAM_SUCCESS )
        log_print( "pam open session error \"%s\"\n", pam_strerror(pamh, err));
}

void close_pam_session(void)
{
    int err;
    if( !pamh ) return;
    err = pam_close_session(pamh, 0);
    //err=pam_setcred(pamh, PAM_DELETE_CRED);
    pam_end(pamh, err);
    pamh = NULL;
}

void append_pam_environ(char **env)
{
	int i,j,n;
	char **penv;
	if(!pamh) return;
	penv=pam_getenvlist(pamh);
	if(!penv) return;
	for(i=0;penv[i]!=NULL;i++)
	{
		//printf("PAM %s\n",penv[i]);
		n=strcspn(penv[i],"=")+1;
		for(j=0;env[j]!=NULL;j++)
		{
			if(!strncmp(penv[i],env[j],n))
				break;
			if(env[j+1]==NULL)
			{
				env[j+1]=g_strdup(penv[i]);
				env[j+2]=NULL;
				break;
			}
		}
		free(penv[i]);
	}
	free(penv);
}

#endif

void switch_user(struct passwd *pw, char *run, char **env)
{
    int fd;

    g_spawn_command_line_sync ("/etc/lxdm/PreLogin",NULL,NULL,NULL,NULL);

    if( !pw || initgroups(pw->pw_name, pw->pw_gid) ||
        setgid(pw->pw_gid) || setuid(pw->pw_uid) || setsid() == -1 )
        exit(EXIT_FAILURE);
    chdir(pw->pw_dir);
    fd=open(".xsession-errors",O_WRONLY|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR);
    if(fd!=-1)
    {
        dup2(fd,STDERR_FILENO);
        close(fd);
    }
#ifndef DISABLE_XAUTH
    create_client_auth(pw->pw_dir,env);
#endif
    g_spawn_command_line_async ("/etc/lxdm/PostLogin",NULL);
    execle("/etc/lxdm/Xsession", "/etc/lxdm/Xsession", run, NULL, env);
    exit(EXIT_FAILURE);
}

void get_lock(void)
{
    FILE *fp;
    char *lockfile;

    lockfile = g_key_file_get_string(config, "base", "lock", 0);
    if( !lockfile ) lockfile = g_strdup("/var/run/lxdm.pid");

    fp = fopen(lockfile, "r");
    if( fp )
    {
        int pid;
        int ret;
        ret = fscanf(fp, "%d", &pid);
        fclose(fp);
        if(ret == 1 && pid!=getpid())
	{
            if(kill(pid, 0) == 0 || (ret == -1 && errno == EPERM))
            {
                /* we should only quit if the pid running is lxdm */
#ifdef __linux__
                char path[64],buf[128];
                sprintf(path,"/proc/%d/exe",pid);
                ret=readlink(path,buf,128);
                if(ret<128 && ret>0 && strstr(buf,"lxdm-binary"))
                    lxdm_quit_self(1);
#else
                lxdm_quit_self(1);
#endif	
            }
	}
    }
    fp = fopen(lockfile, "w");
    if( !fp )
    {
        log_print("open lock file %s fail\n",lockfile);
        lxdm_quit_self(0);
    }
    fprintf( fp, "%d", getpid() );
    fclose(fp);
    g_free(lockfile);
}

void put_lock(void)
{
    FILE *fp;
    char *lockfile;

    lockfile = g_key_file_get_string(config, "base", "lock", 0);
    if( !lockfile ) lockfile = g_strdup("/var/run/lxdm.pid");
    fp = fopen(lockfile, "r");
    if( fp )
    {
        int pid;
        int ret;
        ret = fscanf(fp, "%d", &pid);
        fclose(fp);
        if( ret == 1 && pid == getpid() )
            remove(lockfile);
    }
    g_free(lockfile);
}

void stop_pid(int pid)
{
    if( pid <= 0 ) return;
    if( killpg(pid, SIGTERM) < 0 )
        killpg(pid, SIGKILL);
    if( kill(pid, 0) == 0 )
    {
        if( kill(pid, SIGTERM) )
            kill(pid, SIGKILL);
        while( 1 )
        {
            int wpid, status;
            wpid = wait(&status);
            if( pid == wpid ) break;
        }
    }
    while( waitpid(-1, 0, WNOHANG) > 0 ) ;
}

static int CatchErrors(Display *dpy, XErrorEvent *ev)
{
	return 0;
}

static jmp_buf XErrEnv;
static int CatchIOErrors(Display *dpy)
{
	close(ConnectionNumber(dpy));
	longjmp(XErrEnv,1);
	return 0;
}

static void stop_clients(void)
{
    Window dummy, parent;
    Window *children;
    unsigned int nchildren;
    unsigned int i;
    Display *dpy;
    Window Root;

    dpy=XOpenDisplay(0);
    if(!dpy) return;


    XSetErrorHandler(CatchErrors);
    XSetIOErrorHandler(CatchIOErrors);

    Root = DefaultRootWindow(dpy);

    nchildren = 0;
    if(!setjmp(XErrEnv))
        XQueryTree(dpy, Root, &dummy, &parent, &children, &nchildren);
    else
        goto out;
    for( i = 0; i < nchildren; i++ )
    {
        if(!setjmp(XErrEnv))
            XKillClient(dpy, children[i]);
    }
    XFree( (char *)children );
    if(!setjmp(XErrEnv))
        XSync(dpy, 0);
out:
    if(!setjmp(XErrEnv))
        XCloseDisplay(dpy);
    XSetErrorHandler(NULL);
    XSetIOErrorHandler(NULL);
}

static void on_xserver_stop(void *data,int pid, int status)
{
	log_print("xserver stop, restart. return status %x\n",status);

	stop_pid(server);
	server = -1;

	if(child>0)
		lxcom_del_child_watch(child);
	if( child > 0 )
	{
		killpg(child, SIGHUP);
		stop_pid(child);
		child = -1;
	}
#if HAVE_LIBPAM
	close_pam_session();
#endif
#if HAVE_LIBCK_CONNECTOR
	if( ckc != NULL )
	{
		ck_connector_unref(ckc);
		ckc=NULL;
		unsetenv("XDG_SESSION_COOKIE");
	}
#endif

	lxdm_startx();
	ui_drop();
	ui_prepare();
}

static void set_numlock(Display *dpy)
{
	XkbDescPtr xkb;
	unsigned int mask;
	int on;
	int i;
	if(!g_key_file_has_key(config,"base","numlock",NULL))
		return;
	on=g_key_file_get_integer(config,"base","numlock",0);
	xkb = XkbGetKeyboard( dpy, XkbAllComponentsMask, XkbUseCoreKbd );
	if(!xkb) return;
	if(!xkb->names)
	{
		XkbFreeKeyboard(xkb,0,True);
		return;
	}
	for(i = 0; i < XkbNumVirtualMods; i++)
	{
		char *s=XGetAtomName( xkb->dpy, xkb->names->vmods[i]);
		if(!s) continue;
		if(strcmp(s,"NumLock")) continue;
		XkbVirtualModsToReal( xkb, 1 << i, &mask );
		break;
	}
	XkbFreeKeyboard( xkb, 0, True );
	XkbLockModifiers ( dpy, XkbUseCoreKbd, mask, (on?mask:0));
}

void lxdm_startx(void)
{
	char *arg;
	char **args;
	int i;
	Display *dpy=NULL;

	if(!getenv("DISPLAY"))
		setenv("DISPLAY",":0",1);

	#ifndef DISABLE_XAUTH
	create_server_auth();
	#endif

	arg = g_key_file_get_string(config, "server", "arg", 0);
	if( !arg ) arg = g_strdup("/usr/bin/X");
	args = g_strsplit(arg, " ", -1);
	g_free(arg);

	server = vfork();

	switch( server )
	{
	case 0:
		execvp(args[0], args);
		log_print("exec %s fail\n",args[0]);
		lxdm_quit_self(0);
		break;
	case -1:
	/* fatal error, should not restart self */
		log_print("fork proc fail\n");
		lxdm_quit_self(0);
		break;
	default:
		break;
	}
	g_strfreev(args);
	lxcom_add_child_watch(server, on_xserver_stop, 0);

	for( i = 0; i < 200; i++ )
	{
		if((dpy=XOpenDisplay(0))!=NULL)
			break;
		g_usleep(50 * 1000);
	}
	if( i >= 200 )
		exit(EXIT_FAILURE);
	set_numlock(dpy);
	if(!setjmp(XErrEnv)) XCloseDisplay(dpy);
}

void exit_cb(void)
{
	if( child > 0 )
	{
		lxcom_del_child_watch(child);
		killpg(child, SIGHUP);
		stop_pid(child);
		child = -1;
	}
	ui_clean();
	#if HAVE_LIBPAM
	close_pam_session();
	#endif
	if( server > 0 )
	{
		lxcom_del_child_watch(server);
		stop_pid(server);
		server = -1;
	}
	put_lock();
	set_active_vt(old_tty);
}

static int get_run_level(void)
{
	int res=0;
	struct utmp *ut,tmp;

	setutent();
	tmp.ut_type=RUN_LVL;
	ut=getutid(&tmp);
	if(!ut)
	{
		endutent();
		return 5;
	}
	res=ut->ut_pid & 0xff;
	endutent();
	//log_print("runlevel %c\n",res);
	return res;
}

static void on_session_stop(void *data,int pid, int status)
{
	killpg(pid, SIGHUP);
	stop_pid(pid);
	child = -1;
	int level;

	if( server > 0 )
	{
		/* FIXME just work around lxde bug of focus can't set */
		stop_clients();
	}
	#if HAVE_LIBPAM
	close_pam_session();
	#endif
	#if HAVE_LIBCK_CONNECTOR
	if( ckc != NULL )
	{
		DBusError error;
		dbus_error_init(&error);
		ck_connector_close_session(ckc, &error);
		ck_connector_unref(ckc);
		ckc=NULL;
		unsetenv("XDG_SESSION_COOKIE");
	}
	#endif
	level=get_run_level();
	if(level=='0' || level=='6')
	{
		if(level=='0')
			g_spawn_command_line_sync("/etc/lxdm/PreShutdown",0,0,0,0);
		else
			g_spawn_command_line_sync("/etc/lxdm/PreReboot",0,0,0,0);
		lxdm_quit_self(0);
	}
	ui_prepare();
	g_spawn_command_line_async("/etc/lxdm/PostLogout",NULL);
}

gboolean lxdm_get_session_info(char *session,char **pname,char **pexec)
{
	char *name=NULL,*exec=NULL;
	if(!session || !session[0])
	{
		name=g_key_file_get_string(config, "base", "session", 0);
		if(!name && getenv("PREFERRED"))
			name = g_strdup(getenv("PREFERRED"));
		if(!session && getenv("DESKTOP"))
			name = g_strdup(getenv("DESKTOP"));
		if(!name) name=g_strdup("LXDE");
	}
	else
	{
		char *p=strrchr(session,'.');
		if(p && !strcmp(p,".desktop"))
		{
			GKeyFile *cfg=g_key_file_new();
			if(!g_key_file_load_from_file(cfg,session,G_KEY_FILE_NONE,NULL))
			{
				g_key_file_free(cfg);
				return FALSE;
			}
			name=g_key_file_get_string(cfg,"Desktop Entry","Name",NULL);
			exec=g_key_file_get_string(cfg,"Desktop Entry","Exec",NULL);
			g_key_file_free(cfg);
			if(!name || !exec)
			{
				g_free(name);
				g_free(exec);
				return FALSE;
			}			
		}
		else
		{
			name=g_strdup(session);
		}
	}
	if(name && !exec)
	{
		if(!strcasecmp(name,"LXDE"))
			exec = g_strdup("startlxde");
		else if( !strcasecmp(name, "GNOME") )
			exec = g_strdup("gnome-session");
		else if( !strcasecmp(name, "KDE") )
			exec = g_strdup("startkde");
		else if( !strcasecmp(name, "XFCE") || !strcasecmp(name, "xfce4"))
			exec = g_strdup("startxfce4");
		else
			exec=g_strdup(name);
	}
	if(pname) *pname=name;
	if(pexec) *pexec=exec;
	return TRUE;
}

void lxdm_do_login(struct passwd *pw, char *session, char *lang)
{
	char *session_name=0,*session_exec=0;
	gboolean alloc_session=FALSE,alloc_lang=FALSE;
	int pid;

	if(!session ||!session[0] || !lang || !lang[0])
	{
		char *path=g_strdup_printf("%s/.dmrc",pw->pw_dir);
		GKeyFile *dmrc=g_key_file_new();
		g_key_file_load_from_file(dmrc,path,G_KEY_FILE_NONE,0);
		g_free(path);
		if(!session || !session[0])
		{
			session=g_key_file_get_string(dmrc,"Desktop","Session",NULL);
			alloc_session=TRUE;
		}
		if(!lang || !lang[0])
		{
			lang=g_key_file_get_string(dmrc,"Desktop","Language",NULL);
			alloc_lang=TRUE;
		}
		g_key_file_free(dmrc);
	}

	if(!lxdm_get_session_info(session,&session_name,&session_exec))
	{
		if(alloc_session)
			g_free(session);
		if(alloc_lang)
			g_free(lang);
		ui_prepare();
		dbg_printf("get session %s info fail\n",session);
		return;
	}

	dbg_printf("login user %s session %s lang %s\n",pw->pw_name,session_exec,lang);

	if( pw->pw_shell[0] == '\0' )
	{
		setusershell();
		strcpy( pw->pw_shell, getusershell() );
		endusershell();
	}
	#if HAVE_LIBPAM
	setup_pam_session(pw,session_name);
	#endif
	#if HAVE_LIBCK_CONNECTOR
	if(!ckc)
		ckc = ck_connector_new();
	if( ckc != NULL )
	{
		DBusError error;
		char x[256], *d, *n;
		sprintf(x, "/dev/tty%d", tty);
		dbus_error_init(&error);
		d = x; n = getenv("DISPLAY");
		if( ck_connector_open_session_with_parameters(ckc, &error,
													  "unix-user", &pw->pw_uid,
	// disable this, follow the gdm way 
													  //"display-device", &d,
													  "x11-display-device", &d,
													  "x11-display", &n,
													  NULL) )
			setenv("XDG_SESSION_COOKIE", ck_connector_get_cookie(ckc), 1);
	}
	#endif
	child = pid = fork();
	if( child == 0 )
	{
		char** env, *path;
		int n_env,i;
		n_env  = g_strv_length(environ);
		/* copy all environment variables and override some of them */
		env = g_new(char*, n_env + 1 + 13);
		for( i = 0; i < n_env; ++i )
			env[i] = g_strdup(environ[i]);
		env[i] = NULL;

		replace_env(env, "HOME=", pw->pw_dir);
		replace_env(env, "SHELL=", pw->pw_shell);
		replace_env(env, "USER=", pw->pw_name);
		replace_env(env, "LOGNAME=", pw->pw_name);

		/* override $PATH if needed */
		path = g_key_file_get_string(config, "base", "path", 0);
		if( G_UNLIKELY(path) && path[0] ) /* if PATH is specified in config file */
			replace_env(env, "PATH=", path); /* override current $PATH with config value */
	else /* don't use the global env, they are bad for user */
		replace_env(env, "PATH=", "/usr/local/bin:/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin"); /* set proper default */
		g_free(path);
		/* optionally override $LANG, $LC_MESSAGES, and $LANGUAGE */
		if( lang && lang[0] )
		{
			replace_env(env, "LANG=", lang);
			replace_env(env, "LC_MESSAGES=", lang);
			replace_env(env, "LANGUAGE=", lang);
		} 
	#if HAVE_LIBPAM
	append_pam_environ(env);
	pam_end(pamh,0);
	#endif
	switch_user(pw, session_exec, env);
	lxdm_quit_self(4);
	}
	g_free(session_name);
	g_free(session_exec);
	if(alloc_session)
		g_free(session);
	if(alloc_lang)
		g_free(lang);
	lxcom_add_child_watch(pid, on_session_stop, 0);
}

void lxdm_do_reboot(void)
{
	char *cmd;
	cmd = g_key_file_get_string(config, "cmd", "reboot", 0);
	if( !cmd ) cmd = g_strdup("reboot");
	g_spawn_command_line_sync("/etc/lxdm/PreReboot",0,0,0,0);
	g_spawn_command_line_async(cmd,0);
	g_free(cmd);
	lxdm_quit_self(0);
}

void lxdm_do_shutdown(void)
{
	char *cmd;
	cmd = g_key_file_get_string(config, "cmd", "shutdown", 0);
	if( !cmd ) cmd = g_strdup("shutdown -h now");
	g_spawn_command_line_sync("/etc/lxdm/PreReboot",0,0,0,0);
	g_spawn_command_line_async(cmd,0);
	g_free(cmd);
	lxdm_quit_self(0);
}

int lxdm_cur_session(void)
{
	return child;
}

int lxdm_do_auto_login(void)
{
	struct passwd *pw;
	char *user;
	char *pass=NULL;
	int ret;


	user = g_key_file_get_string(config, "base", "autologin", 0);
	if( !user )
		return 0;

	#ifdef ENABLE_PASSWORD
	pass = g_key_file_get_string(config, "base", "password", 0);
	#endif
	ret=lxdm_auth_user(user, pass, &pw);
	g_free(user);
	g_free(pass);
	if(ret!=AUTH_SUCCESS)
		return 0;
	lxdm_do_login(pw, NULL, NULL);
	return 1;
}

static void log_sigsegv(void)
{
	void *array[40];
	size_t size;
	int fd;

	fd=open("/var/log/lxdm.log",O_WRONLY|O_CREAT|O_APPEND,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if(fd==-1) return;

	size=backtrace(array,40);
	backtrace_symbols_fd(array,size,fd);

	close(fd);
}

static void sigsegv_handler(int sig)
{
	switch( sig )
	{
	case SIGSEGV:
		log_sigsegv();
	lxdm_quit_self(0);
		break;
	default:
		break;
	}
}

static void lxdm_signal_handler(void *data,int sig)
{
	switch( sig )
	{
	case SIGTERM:
	case SIGINT:
		lxdm_quit_self(0);
		break;
	default:
		break;
	}
}

void set_signal(void)
{
	lxcom_set_signal_handler(SIGQUIT,lxdm_signal_handler,0);
	lxcom_set_signal_handler(SIGTERM,lxdm_signal_handler,0);
	lxcom_set_signal_handler(SIGKILL,lxdm_signal_handler,0);
	lxcom_set_signal_handler(SIGINT,lxdm_signal_handler,0);
	lxcom_set_signal_handler(SIGHUP,lxdm_signal_handler,0);
	lxcom_set_signal_handler(SIGPIPE,lxdm_signal_handler,0);
	lxcom_set_signal_handler(SIGUSR1,lxdm_signal_handler,0);
	lxcom_set_signal_handler(SIGALRM,lxdm_signal_handler,0);
	signal(SIGSEGV, sigsegv_handler);
}

int main(int arc, char *arg[])
{
	int daemonmode = 0;
	int i;


	for(i=1;i<arc;i++)
	{
		if(!strcmp(arg[i],"-d"))
			daemonmode=1;
		else if(!strcmp(arg[i],"-c") && i+1<arc)
		{
			int count=strlen(arg[i+1])+1;
			i=lxcom_send("/tmp/lxdm.sock",arg[i+1],count);
			return (i==count)?0:-1;
		}
	}
	if( getuid() != 0 )
	{
		printf("only root is allowed to use this program\n");
		exit(EXIT_FAILURE);
	}

	if( daemonmode )
		(void)daemon(1, 1);

	config = g_key_file_new();
	g_key_file_load_from_file(config, CONFIG_FILE, G_KEY_FILE_NONE, NULL);

	get_lock();
	lxcom_init("/tmp/lxdm.sock");
	atexit(exit_cb);

	set_signal();
	lxdm_get_tty();
	lxdm_startx();

	lxdm_do_auto_login();

	ui_main();

	return 0;
}

