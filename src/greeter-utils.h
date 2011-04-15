#ifndef _GREETER_UTILS_H_
#define _GREETER_UTILS_H_

void ui_set_bg(GdkWindow *win,GKeyFile *config);
void ui_set_focus(GdkWindow *win);
void ui_add_cursor(void);
void ui_set_cursor(GdkWindow *win,int which);

#endif/*_GREETER_UTILS_H_*/
