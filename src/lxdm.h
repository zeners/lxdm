#ifndef _LXDM_H_
#define _LXDM_H_

#include <pwd.h>

extern GKeyFile *config;

void log_print(char *fmt,...);
int lxdm_auth_user(char *user,char *pass,struct passwd **ppw);
void lxdm_do_login(struct passwd *pw,char *session,char *lang);
void lxdm_do_reboot(void);
void lxdm_do_shutdown(void);
int lxdm_cur_session(void);

#define AUTH_SUCCESS	0
#define AUTH_BAD_USER	1
#define AUTH_FAIL	2
#define AUTH_PRIV	3
#define AUTH_ERROR	4

void ui_drop(void);
int ui_main(void);
void ui_prepare(void);
int ui_do_login(void);

typedef struct{
	char *name;
	char *exec;
}LXSESSION;

GSList *do_scan_xsessions(void);
void free_xsessions(GSList *);

#endif/*_LXDM_H_*/
