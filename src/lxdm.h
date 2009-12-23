/*
 *      lxdm.h - interface of lxdm
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
