#ifndef _LXDM_H_
#define _LXDM_H_

#include <pwd.h>
#include <gtk/gtk.h>

extern GKeyFile *config;

void log_print(char *fmt,...);
int auth_user(char *user,char *pass,struct passwd **ppw);
void do_login(struct passwd *pw,char *session);
void do_reboot(void);
void do_shutdown(void);

#define AUTH_SUCCESS	0
#define AUTH_BAD_USER	1
#define AUTH_FAIL	2
#define AUTH_PRIV	3
#define AUTH_ERROR	4

int gtk_ui_main(void);

int ui_set_bg(void);

#endif/*_LXDM_H_*/
