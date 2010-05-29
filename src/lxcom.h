#ifndef _LXCOM_H_
#define LXCOM_H_

void lxcom_init(const char *sock);
void lxcom_raise_signal(int sig);
ssize_t lxcom_send(const char *sock,const void *buf,ssize_t count);
int lxcom_add_child_watch(int pid,void (*func)(void*,int,int),void *data);
int lxcom_del_child_watch(int pid);
int lxcom_set_signal_handler(int sig,void (*func)(void *,int),void *data);
int lxcom_add_cmd_handler(int user,void (*func)(void *,int,int,char **),void *data);
int lxcom_del_cmd_handler(int user);

#endif/*_LXCOM_H_*/
