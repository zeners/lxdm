#include <gdk/gdk.h>
#include <gdk/gdkx.h>
#include <X11/Xlib.h>
#include <string.h>
#include <cairo.h>
#include <cairo-xlib.h>

#ifdef ENABLE_GTK3

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
#define GIMP_CAIRO_RGB24_SET_PIXEL(d, r, g, b) \
  G_STMT_START { d[0] = (b);  d[1] = (g);  d[2] = (r); } G_STMT_END
#else
#define GIMP_CAIRO_RGB24_SET_PIXEL(d, r, g, b) \
  G_STMT_START { d[1] = (r);  d[2] = (g);  d[3] = (b); } G_STMT_END
#endif


/**
 * GIMP_CAIRO_RGB24_GET_PIXEL:
 * @s: pointer to the source buffer
 * @r: red component
 * @g: green component
 * @b: blue component
 *
 * Gets a single pixel from a Cairo image surface in %CAIRO_FORMAT_RGB24.
 *
 * Since: GIMP 2.8
 **/
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
#define GIMP_CAIRO_RGB24_GET_PIXEL(s, r, g, b) \
  G_STMT_START { (b) = s[0]; (g) = s[1]; (r) = s[2]; } G_STMT_END
#else
#define GIMP_CAIRO_RGB24_GET_PIXEL(s, r, g, b) \
  G_STMT_START { (r) = s[1]; (g) = s[2]; (b) = s[3]; } G_STMT_END
#endif


/**
 * GIMP_CAIRO_ARGB32_SET_PIXEL:
 * @d: pointer to the destination buffer
 * @r: red component, not pre-multiplied
 * @g: green component, not pre-multiplied
 * @b: blue component, not pre-multiplied
 * @a: alpha component
 *
 * Sets a single pixel in an Cairo image surface in %CAIRO_FORMAT_ARGB32.
 *
 * Since: GIMP 2.6
 **/
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
#define GIMP_CAIRO_ARGB32_SET_PIXEL(d, r, g, b, a) \
  G_STMT_START {                                   \
    const guint tr = (a) * (r) + 0x80;             \
    const guint tg = (a) * (g) + 0x80;             \
    const guint tb = (a) * (b) + 0x80;             \
    (d)[0] = (((tb) >> 8) + (tb)) >> 8;            \
    (d)[1] = (((tg) >> 8) + (tg)) >> 8;            \
    (d)[2] = (((tr) >> 8) + (tr)) >> 8;            \
    (d)[3] = (a);                                  \
  } G_STMT_END
#else
#define GIMP_CAIRO_ARGB32_SET_PIXEL(d, r, g, b, a) \
  G_STMT_START {                                   \
    const guint tr = (a) * (r) + 0x80;             \
    const guint tg = (a) * (g) + 0x80;             \
    const guint tb = (a) * (b) + 0x80;             \
    (d)[0] = (a);                                  \
    (d)[1] = (((tr) >> 8) + (tr)) >> 8;            \
    (d)[2] = (((tg) >> 8) + (tg)) >> 8;            \
    (d)[3] = (((tb) >> 8) + (tb)) >> 8;            \
  } G_STMT_END
#endif

cairo_surface_t *
gimp_cairo_surface_create_from_pixbuf (GdkPixbuf *pixbuf)
{
  cairo_surface_t *surface;
  cairo_format_t   format;
  guchar          *dest;
  const guchar    *src;
  gint             width;
  gint             height;
  gint             src_stride;
  gint             dest_stride;
  gint             y;

  g_return_val_if_fail (GDK_IS_PIXBUF (pixbuf), NULL);

  width  = gdk_pixbuf_get_width (pixbuf);
  height = gdk_pixbuf_get_height (pixbuf);

  switch (gdk_pixbuf_get_n_channels (pixbuf))
    {
    case 3:
      format = CAIRO_FORMAT_RGB24;
      break;
    case 4:
      format = CAIRO_FORMAT_ARGB32;
      break;
    default:
      g_assert_not_reached ();
      break;
    }

  surface = cairo_image_surface_create (format, width, height);

  cairo_surface_flush (surface);

  src         = gdk_pixbuf_get_pixels (pixbuf);
  src_stride  = gdk_pixbuf_get_rowstride (pixbuf);

  dest        = cairo_image_surface_get_data (surface);
  dest_stride = cairo_image_surface_get_stride (surface);

  switch (format)
    {
    case CAIRO_FORMAT_RGB24:
      for (y = 0; y < height; y++)
        {
          const guchar *s = src;
          guchar       *d = dest;
          gint          w = width;

          while (w--)
            {
              GIMP_CAIRO_RGB24_SET_PIXEL (d, s[0], s[1], s[2]);

              s += 3;
              d += 4;
            }

          src  += src_stride;
          dest += dest_stride;
        }
      break;

    case CAIRO_FORMAT_ARGB32:
      for (y = 0; y < height; y++)
        {
          const guchar *s = src;
          guchar       *d = dest;
          gint          w = width;

          while (w--)
            {
              GIMP_CAIRO_ARGB32_SET_PIXEL (d, s[0], s[1], s[2], s[3]);

              s += 4;
              d += 4;
            }

          src  += src_stride;
          dest += dest_stride;
        }
      break;

    default:
      break;
    }

  cairo_surface_mark_dirty (surface);

  return surface;
}
#endif


static cairo_surface_t *cairo_surface_create_from_pixbuf (GdkWindow *root,GdkPixbuf *pixbuf)
{
	Display *dpy=GDK_WINDOW_XDISPLAY(root);
	int scr=DefaultScreen(dpy);
	Visual *visual=DefaultVisual(dpy,scr);
	gint width=gdk_pixbuf_get_width(pixbuf);
	gint height=gdk_pixbuf_get_height(pixbuf);
	Pixmap pix=XCreatePixmap(dpy,GDK_WINDOW_XID(root),width,height,DefaultDepth(dpy,scr));
	cairo_surface_t *surface=cairo_xlib_surface_create(dpy,pix,visual,width,height);
	cairo_t *cr=cairo_create(surface);
	gdk_cairo_set_source_pixbuf(cr,pixbuf,0,0);
	cairo_paint(cr);
	cairo_destroy(cr);
	return surface;
}

void ui_set_bg(GdkWindow *win,GKeyFile *config)
{
	GdkPixbuf *bg_img=NULL;
	GdkColor bg_color;
	GdkWindow *root=gdk_get_default_root_window();
	char *p=g_key_file_get_string(config,"display","bg",NULL);
	gdk_color_parse("#222E45",&bg_color);
	if( p && p[0] != '#' )
    {
        bg_img = gdk_pixbuf_new_from_file(p, 0);
    }
    if( p && p[0] == '#' )
    {
		gdk_color_parse(p, &bg_color);
	}
	g_free(p);

    /* set background */
	if( bg_img )
	{
		p = g_key_file_get_string(config, "display", "bg_style", 0);
		if( !p || !strcmp(p, "stretch") )
		{
			GdkPixbuf *pb = gdk_pixbuf_scale_simple(bg_img,
													gdk_screen_width(),
													gdk_screen_height(),
													GDK_INTERP_HYPER);
			g_object_unref(bg_img);
			bg_img = pb;
		}
		g_free(p);

#ifdef ENABLE_GTK3
		cairo_surface_t *surface;
		cairo_pattern_t *pattern;
		surface=cairo_surface_create_from_pixbuf(root,bg_img);
		pattern=cairo_pattern_create_for_surface(surface);
		g_object_unref(bg_img);
		if(win) gdk_window_set_background_pattern(win,pattern);
		gdk_window_set_background_pattern(root,pattern);
		cairo_pattern_destroy(pattern);
#else
		GdkPixmap *pix = NULL;
		gdk_pixbuf_render_pixmap_and_mask(bg_img, &pix, NULL, 0);
		g_object_unref(bg_img);
		if(win) gdk_window_set_back_pixmap(win,pix,FALSE);
		gdk_window_set_back_pixmap(root,pix,FALSE);
		g_object_unref(pix);
#endif
	}
	else
	{
#ifdef ENABLE_GTK3
		if(win) gdk_window_set_background(win,&bg_color);
		gdk_window_set_background(root,&bg_color);
#else
		GdkColormap *map;
		if(win)
		{
			map=(GdkColormap*)gdk_drawable_get_colormap(win);
			gdk_colormap_alloc_color(map, &bg_color, TRUE, TRUE);
			gdk_window_set_background(win, &bg_color);
		}
        map=(GdkColormap*)gdk_drawable_get_colormap(root);
		gdk_colormap_alloc_color(map, &bg_color, TRUE, TRUE);
        gdk_window_set_background(root, &bg_color);
#endif
	}
}

void ui_set_focus(GdkWindow *win)
{
	Display *dpy=gdk_x11_display_get_xdisplay(gdk_window_get_display(win));
	gdk_flush();
	while(1)
	{
		XWindowAttributes attr;
    	XGetWindowAttributes(dpy,GDK_WINDOW_XID(win),&attr);
    	if(attr.map_state == IsViewable) break;
    	usleep(10000);
	}
	XSetInputFocus(dpy,GDK_WINDOW_XID(win),RevertToNone,CurrentTime);
}

void ui_add_cursor(void)
{
    GdkCursor *cur;
    GdkWindow *root=gdk_get_default_root_window();
    cur = gdk_cursor_new(GDK_LEFT_PTR);
    gdk_window_set_cursor(root, cur);
    gdk_cursor_unref(cur);
}

void ui_set_cursor(GdkWindow *win,int which)
{
	GdkCursor *cursor=gdk_cursor_new(which);
	gdk_window_set_cursor (win,cursor);
	gdk_cursor_unref(cursor);
}

