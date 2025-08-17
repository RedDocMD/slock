/* See LICENSE file for license details. */
#define _XOPEN_SOURCE 500
#if HAVE_SHADOW_H
#include <shadow.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <X11/extensions/Xrandr.h>
#include <X11/keysym.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <pthread.h>
#include <cairo/cairo-xlib.h>

#include "arg.h"
#include "util.h"

char *argv0;
static int pam_conv(int num_msg, const struct pam_message **msg,
		    struct pam_response **resp, void *appdata_ptr);
char passwd[256];

enum { INIT, INPUT, FAILED, PAM, NUMCOLS };

struct lock {
	int screen;
	Window root, win;
	Pixmap pmap;
	unsigned long colors[NUMCOLS];
};

struct xrandr {
	int active;
	int evbase;
	int errbase;
};

enum {
	CMD_RUN_PAM = 1,
	CMD_PRINT,
	CMD_INPUT,
	CMD_SUCCESS,
	CMD_FAILURE,
};

struct pam_thread_args {
	int rx_fd;
	int tx_fd;
	char *inp_str;
	char *out_str;
	char *hash;
	int dgid;
	int duid;
};

enum {
	ST_NORMAL,
	ST_PAM_STARTED,
	ST_PAM_INPUT,
	ST_DONE,
};

#include "config.h"

static void die(const char *errstr, ...)
{
	va_list ap;

	va_start(ap, errstr);
	vfprintf(stderr, errstr, ap);
	va_end(ap);
	exit(1);
}

#ifdef __linux__
#include <fcntl.h>
#include <linux/oom.h>

static void dontkillme(void)
{
	FILE *f;
	const char oomfile[] = "/proc/self/oom_score_adj";

	if (!(f = fopen(oomfile, "w"))) {
		if (errno == ENOENT)
			return;
		die("slock: fopen %s: %s\n", oomfile, strerror(errno));
	}
	fprintf(f, "%d", OOM_SCORE_ADJ_MIN);
	if (fclose(f)) {
		if (errno == EACCES)
			die("slock: unable to disable OOM killer. "
			    "Make sure to suid or sgid slock.\n");
		else
			die("slock: fclose %s: %s\n", oomfile, strerror(errno));
	}
}
#endif

static void drop_privilleges(int dgid, int duid)
{
	if (setgroups(0, NULL) < 0)
		die("slock: setgroups: %s\n", strerror(errno));
	if (setgid(dgid) < 0)
		die("slock: setgid: %s\n", strerror(errno));
	if (setuid(duid) < 0)
		die("slock: setuid: %s\n", strerror(errno));
}

static const char *gethash(void)
{
	const char *hash;
	struct passwd *pw;

	/* Check if the current user has a password entry */
	errno = 0;
	if (!(pw = getpwuid(getuid()))) {
		if (errno)
			die("slock: getpwuid: %s\n", strerror(errno));
		else
			die("slock: cannot retrieve password entry\n");
	}
	hash = pw->pw_passwd;

#if HAVE_SHADOW_H
	if (!strcmp(hash, "x")) {
		struct spwd *sp;
		if (!(sp = getspnam(pw->pw_name)))
			die("slock: getspnam: cannot retrieve shadow entry. "
			    "Make sure to suid or sgid slock.\n");
		hash = sp->sp_pwdp;
	}
#else
	if (!strcmp(hash, "*")) {
#ifdef __OpenBSD__
		if (!(pw = getpwuid_shadow(getuid())))
			die("slock: getpwnam_shadow: cannot retrieve shadow entry. "
			    "Make sure to suid or sgid slock.\n");
		hash = pw->pw_passwd;
#else
		die("slock: getpwuid: cannot retrieve shadow entry. "
		    "Make sure to suid or sgid slock.\n");
#endif /* __OpenBSD__ */
	}
#endif /* HAVE_SHADOW_H */

	/* pam, store user name */
	hash = pw->pw_name;
	return hash;
}

static void read_cmd(int fd, uint64_t *cmd)
{
	if (read(fd, cmd, sizeof(*cmd)) != sizeof(*cmd))
		die("Failed to read from fd: %s\n", strerror(errno));
}

static void write_cmd(int fd, uint64_t *cmd)
{
	if (write(fd, cmd, sizeof(*cmd)) != sizeof(*cmd))
		die("Failed to write from fd: %s\n", strerror(errno));
}

static int pam_conv(int num_msg, const struct pam_message **msgs,
		    struct pam_response **resp, void *arg)
{
	struct pam_thread_args *ptarg = arg;
	const struct pam_message *msg = *msgs;
	struct pam_response *resp_msg;
	uint64_t cmd;

	if (num_msg != 1)
		die("Too many PAM messages: %d\n", num_msg);

	free(ptarg->out_str);
	ptarg->out_str = strdup(msg->msg);

	switch (msg->msg_style) {
	case PAM_PROMPT_ECHO_OFF:
	case PAM_PROMPT_ECHO_ON:
		cmd = CMD_INPUT;
		write_cmd(ptarg->tx_fd, &cmd);
		read_cmd(ptarg->rx_fd, &cmd);
		if (cmd != CMD_INPUT)
			die("Unexpected command: %d\n", CMD_INPUT);
		resp_msg = malloc(sizeof(struct pam_response));
		resp_msg->resp_retcode = 0;
		resp_msg->resp = strdup(ptarg->inp_str);
		*resp = resp_msg;
		break;
	case PAM_ERROR_MSG:
	case PAM_TEXT_INFO:
		cmd = CMD_PRINT;
		write_cmd(ptarg->tx_fd, &cmd);
		break;
	}
	return PAM_SUCCESS;
}

static void *pam_thread_func(void *arg)
{
	struct pam_thread_args *ptarg = arg;
	uint64_t cmd;
	pam_handle_t *pamh;
	struct pam_conv pamc = { pam_conv, arg };
	int retval;

#ifdef __linux__
	dontkillme();
#endif

	while (1) {
		read_cmd(ptarg->rx_fd, &cmd);
		if (cmd != CMD_RUN_PAM)
			continue;
		retval = pam_start(pam_service, ptarg->hash, &pamc, &pamh);
		if (retval == PAM_SUCCESS)
			retval = pam_authenticate(pamh, 0);
		if (retval == PAM_SUCCESS)
			retval = pam_acct_mgmt(pamh, 0);
		if (retval == PAM_SUCCESS)
			cmd = CMD_SUCCESS;
		else
			cmd = CMD_FAILURE;
		pam_end(pamh, retval);
		write_cmd(ptarg->tx_fd, &cmd);
	}

	return NULL;
}

static void epoll_add(int ep_fd, int fd)
{
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
		die("Failed to add %d to epoll fd %d: %s\n", fd, ep_fd,
		    strerror(errno));
}

static void show_text(Display *dpy, Window win, int screen, char *text,
		      cairo_t *cr, cairo_surface_t *sfc)
{
	int xpos, ypos;
	XRRScreenResources *res;
	XRRCrtcInfo *crtc;
	cairo_text_extents_t dim;

	XClearWindow(dpy, win);
	cairo_set_source_rgb(cr, font_color.r, font_color.g, font_color.b);
	cairo_select_font_face(cr, font, CAIRO_FONT_SLANT_NORMAL,
			       CAIRO_FONT_WEIGHT_BOLD);
	cairo_set_font_size(cr, font_size);
	cairo_text_extents(cr, text, &dim);

	if (!(res = XRRGetScreenResourcesCurrent(dpy, win)))
		die("Failed to get screen resources\n");
	for (int i = 0; i < res->ncrtc; i++) {
		crtc = XRRGetCrtcInfo(dpy, res, res->crtcs[i]);
		if (!crtc)
			continue;
		if (crtc->noutput > 0 && crtc->width > 0 && crtc->height > 0) {
			xpos = crtc->x + crtc->width / 2 - (int)dim.width / 2;
			ypos = crtc->y + crtc->height / 2 - (int)dim.height / 2;
			cairo_move_to(cr, xpos, ypos);
			cairo_show_text(cr, text);
		}
		XRRFreeCrtcInfo(crtc);
	}
	XRRFreeScreenResources(res);
	cairo_surface_flush(sfc);
	XFlush(dpy);
}

static void show_text_all_screens(Display *dpy, struct lock **locks,
				  cairo_surface_t **surfaces, cairo_t **crs,
				  int nscreens, char *msg, int pwlen)
{
	if (!msg)
		return;
	int totlen, msglen;
	char *pwmsg;
	msglen = strlen(msg);
	totlen = msglen + pwlen;
	pwmsg = malloc(totlen + 1);
	strcpy(pwmsg, msg);
	memset(pwmsg + msglen, '*', pwlen);
	pwmsg[totlen] = '\0';
	for (int i = 0; i < nscreens; i++)
		show_text(dpy, locks[i]->win, locks[i]->screen, pwmsg, crs[i],
			  surfaces[i]);
	free(pwmsg);
}

static void readpw(Display *dpy, struct xrandr *rr, struct lock **locks,
		   int nscreens, const char *hash, struct pam_thread_args *args)
{
	XRRScreenChangeNotifyEvent *rre;
	char buf[32], *msg;
	int num, screen, running, failure, oldc, nfds, ep_fd,
		disp_fd = ConnectionNumber(dpy), state = ST_NORMAL, disp_ev = 0,
		rd_ev = 0, repaint = 0, pwch = 0;
	unsigned int len, color;
	KeySym ksym;
	XEvent ev;
	struct epoll_event epv[2];
	uint64_t cmd;
	cairo_surface_t **surfaces;
	cairo_t **crs;
	Drawable win;

	surfaces = calloc(nscreens, sizeof(*surfaces));
	crs = calloc(nscreens, sizeof(*crs));
	for (int k = 0; k < nscreens; k++) {
		win = locks[k]->win;
		screen = locks[k]->screen;
		XMapWindow(dpy, win);
		surfaces[k] = cairo_xlib_surface_create(
			dpy, win, DefaultVisual(dpy, screen),
			DisplayWidth(dpy, screen), DisplayHeight(dpy, screen));
		crs[k] = cairo_create(surfaces[k]);
	}

	len = 0;
	running = 1;
	failure = 0;
	oldc = INIT;
	msg = NULL;

	if ((ep_fd = epoll_create1(0)) < 0)
		die("Failed to create epoll fd: %s", strerror(errno));
	epoll_add(ep_fd, args->tx_fd);
	epoll_add(ep_fd, disp_fd);

	while (running) {
		if ((nfds = epoll_wait(ep_fd, epv, 2, -1)) < 0) {
			if (errno == EINTR) {
				fprintf(stderr, "epoll_wait interrupted\n");
				sleep(1);
				continue;
			}
			die("epoll failed: %s", strerror(errno));
		}

		rd_ev = 0;
		disp_ev = 0;
		repaint = 0;
		pwch = 0;

		for (int i = 0; i < nfds; i++) {
			if (epv[i].data.fd == disp_fd) {
				XNextEvent(dpy, &ev);
				disp_ev = 1;
			} else {
				read_cmd(epv[i].data.fd, &cmd);
				rd_ev = 1;
			}
		}
		if (rd_ev) {
			switch (state) {
			case ST_NORMAL:
			case ST_PAM_INPUT:
				die("Cannot receive command in NORMAL or PAM_INPUT state\n");
			case ST_PAM_STARTED:
				if (cmd == CMD_PRINT) {
					free(msg);
					msg = strdup(args->out_str);
					show_text_all_screens(dpy, locks,
							      surfaces, crs,
							      nscreens, msg,
							      len);
				} else if (cmd == CMD_INPUT) {
					free(msg);
					msg = strdup(args->out_str);
					show_text_all_screens(dpy, locks,
							      surfaces, crs,
							      nscreens, msg,
							      len);
					state = ST_PAM_INPUT;
				} else if (cmd == CMD_SUCCESS) {
					running = 0;
					state = ST_DONE;
					continue;
				} else if (cmd == CMD_FAILURE) {
					failure = 1;
					repaint = 1;
					state = ST_NORMAL;
					free(msg);
					msg = NULL;
					XSync(dpy, False);
					XBell(dpy, 100);
				}
			}
		}
		if (disp_ev && ev.type == KeyPress) {
			explicit_bzero(&buf, sizeof(buf));
			num = XLookupString(&ev.xkey, buf, sizeof(buf), &ksym,
					    0);
			if (IsKeypadKey(ksym)) {
				if (ksym == XK_KP_Enter)
					ksym = XK_Return;
				else if (ksym >= XK_KP_0 && ksym <= XK_KP_9)
					ksym = (ksym - XK_KP_0) + XK_0;
			}
			if (IsFunctionKey(ksym) || IsKeypadKey(ksym) ||
			    IsMiscFunctionKey(ksym) || IsPFKey(ksym) ||
			    IsPrivateKeypadKey(ksym))
				continue;
			switch (ksym) {
			case XK_Return:
				if (state == ST_NORMAL &&
				    ev.xkey.state & ShiftMask) {
					state = ST_PAM_STARTED;
					cmd = CMD_RUN_PAM;
					write_cmd(args->rx_fd, &cmd);
					repaint = 1;
				} else if (state == ST_PAM_INPUT) {
					passwd[len] = '\0';
					free(args->inp_str);
					args->inp_str = strdup(passwd);
					cmd = CMD_INPUT;
					write_cmd(args->rx_fd, &cmd);
					explicit_bzero(&passwd, sizeof(passwd));
					len = 0;
					state = ST_PAM_STARTED;
					repaint = 1;
				}
				break;
			case XK_Escape:
				if (state == ST_PAM_INPUT) {
					explicit_bzero(&passwd, sizeof(passwd));
					len = 0;
					repaint = 1;
					pwch = 1;
				}
				break;
			case XK_BackSpace:
				if (state == ST_PAM_INPUT) {
					if (len) {
						passwd[--len] = '\0';
						repaint = 1;
						pwch = 1;
					}
				}
				break;
			default:
				if (state == ST_PAM_INPUT) {
					if (num && !iscntrl((int)buf[0]) &&
					    (len + num < sizeof(passwd))) {
						memcpy(passwd + len, buf, num);
						len += num;
						repaint = 1;
						pwch = 1;
					}
				}
				break;
			}
		} else if (rr->active &&
			   ev.type == rr->evbase + RRScreenChangeNotify) {
			rre = (XRRScreenChangeNotifyEvent *)&ev;
			for (screen = 0; screen < nscreens; screen++) {
				if (locks[screen]->win == rre->window) {
					if (rre->rotation == RR_Rotate_90 ||
					    rre->rotation == RR_Rotate_270)
						XResizeWindow(
							dpy, locks[screen]->win,
							rre->height,
							rre->width);
					else
						XResizeWindow(
							dpy, locks[screen]->win,
							rre->width,
							rre->height);
					XClearWindow(dpy, locks[screen]->win);
					break;
				}
			}
			show_text_all_screens(dpy, locks, surfaces, crs,
					      nscreens, msg, len);
		} else {
			for (screen = 0; screen < nscreens; screen++)
				XRaiseWindow(dpy, locks[screen]->win);
		}
		if (repaint) {
			color = len ? INPUT :
				      ((failure || failonclear) ? FAILED :
								  INIT);
			if (state == ST_PAM_STARTED) {
				color = PAM;
			}
			if (running && oldc != color) {
				for (screen = 0; screen < nscreens; screen++) {
					XSetWindowBackground(
						dpy, locks[screen]->win,
						locks[screen]->colors[color]);
					XClearWindow(dpy, locks[screen]->win);
				}
				oldc = color;
				XFlush(dpy);
			}
			if (pwch) {
				show_text_all_screens(dpy, locks, surfaces, crs,
						      nscreens, msg, len);
			}
		}
	}
}

static struct lock *lockscreen(Display *dpy, struct xrandr *rr, int screen)
{
	char curs[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	int i, ptgrab, kbgrab;
	struct lock *lock;
	XColor color, dummy;
	XSetWindowAttributes wa;
	Cursor invisible;

	if (dpy == NULL || screen < 0 || !(lock = malloc(sizeof(struct lock))))
		return NULL;

	lock->screen = screen;
	lock->root = RootWindow(dpy, lock->screen);

	for (i = 0; i < NUMCOLS; i++) {
		XAllocNamedColor(dpy, DefaultColormap(dpy, lock->screen),
				 colorname[i], &color, &dummy);
		lock->colors[i] = color.pixel;
	}

	/* init */
	wa.override_redirect = 1;
	wa.background_pixel = lock->colors[INIT];
	lock->win = XCreateWindow(dpy, lock->root, 0, 0,
				  DisplayWidth(dpy, lock->screen),
				  DisplayHeight(dpy, lock->screen), 0,
				  DefaultDepth(dpy, lock->screen),
				  CopyFromParent,
				  DefaultVisual(dpy, lock->screen),
				  CWOverrideRedirect | CWBackPixel, &wa);
	lock->pmap = XCreateBitmapFromData(dpy, lock->win, curs, 8, 8);
	invisible = XCreatePixmapCursor(dpy, lock->pmap, lock->pmap, &color,
					&color, 0, 0);
	XDefineCursor(dpy, lock->win, invisible);

	/* Try to grab mouse pointer *and* keyboard for 600ms, else fail the lock */
	for (i = 0, ptgrab = kbgrab = -1; i < 6; i++) {
		if (ptgrab != GrabSuccess) {
			ptgrab = XGrabPointer(dpy, lock->root, False,
					      ButtonPressMask |
						      ButtonReleaseMask |
						      PointerMotionMask,
					      GrabModeAsync, GrabModeAsync,
					      None, invisible, CurrentTime);
		}
		if (kbgrab != GrabSuccess) {
			kbgrab = XGrabKeyboard(dpy, lock->root, True,
					       GrabModeAsync, GrabModeAsync,
					       CurrentTime);
		}

		/* input is grabbed: we can lock the screen */
		if (ptgrab == GrabSuccess && kbgrab == GrabSuccess) {
			XMapRaised(dpy, lock->win);
			if (rr->active)
				XRRSelectInput(dpy, lock->win,
					       RRScreenChangeNotifyMask);

			XSelectInput(dpy, lock->root, SubstructureNotifyMask);
			return lock;
		}

		/* retry on AlreadyGrabbed but fail on other errors */
		if ((ptgrab != AlreadyGrabbed && ptgrab != GrabSuccess) ||
		    (kbgrab != AlreadyGrabbed && kbgrab != GrabSuccess))
			break;

		usleep(100000);
	}

	/* we couldn't grab all input: fail out */
	if (ptgrab != GrabSuccess)
		fprintf(stderr,
			"slock: unable to grab mouse pointer for screen %d\n",
			screen);
	if (kbgrab != GrabSuccess)
		fprintf(stderr,
			"slock: unable to grab keyboard for screen %d\n",
			screen);
	return NULL;
}

static void usage(void)
{
	die("usage: slock [-v] [cmd [arg ...]]\n");
}

int main(int argc, char **argv)
{
	struct xrandr rr;
	struct lock **locks;
	struct passwd *pwd;
	struct group *grp;
	uid_t duid;
	gid_t dgid;
	const char *hash;
	Display *dpy;
	int s, nlocks, nscreens;
	struct pam_thread_args pargs;
	pthread_t ptid;

	freopen(log_file, "w", stdout);
	freopen(log_file, "w", stderr);

	ARGBEGIN
	{
	case 'v':
		puts("slock-" VERSION);
		return 0;
	default:
		usage();
	}
	ARGEND

	/* validate drop-user and -group */
	errno = 0;
	if (!(pwd = getpwnam(user)))
		die("slock: getpwnam %s: %s\n", user,
		    errno ? strerror(errno) : "user entry not found");
	duid = pwd->pw_uid;
	errno = 0;
	if (!(grp = getgrnam(group)))
		die("slock: getgrnam %s: %s\n", group,
		    errno ? strerror(errno) : "group entry not found");
	dgid = grp->gr_gid;

#ifdef __linux__
	dontkillme();
#endif

	/* the contents of hash are used to transport the current user name */
	hash = gethash();
	errno = 0;

	explicit_bzero(&pargs, sizeof(pargs));
	pargs.hash = strdup(hash);
	pargs.dgid = dgid;
	pargs.duid = duid;
	if ((pargs.rx_fd = eventfd(0, 0)) < 0)
		die("Failed to create eventfd: %s", strerror(errno));
	if ((pargs.tx_fd = eventfd(0, 0)) < 0)
		die("Failed to create eventfd: %s", strerror(errno));
	if (pthread_create(&ptid, NULL, pam_thread_func, &pargs) != 0)
		die("Failed to spawn pam thread\n");

	if (!(dpy = XOpenDisplay(NULL)))
		die("slock: cannot open display\n");

	drop_privilleges(dgid, duid);

	/* check for Xrandr support */
	rr.active = XRRQueryExtension(dpy, &rr.evbase, &rr.errbase);

	/* get number of screens in display "dpy" and blank them */
	nscreens = ScreenCount(dpy);
	if (!(locks = calloc(nscreens, sizeof(struct lock *))))
		die("slock: out of memory\n");
	for (nlocks = 0, s = 0; s < nscreens; s++) {
		if ((locks[s] = lockscreen(dpy, &rr, s)) != NULL)
			nlocks++;
		else
			break;
	}
	XSync(dpy, 0);

	/* did we manage to lock everything? */
	if (nlocks != nscreens)
		return 1;

	/* run post-lock command */
	if (argc > 0) {
		pid_t pid;
		extern char **environ;
		int err =
			posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ);
		if (err) {
			die("slock: failed to execute post-lock command: %s: %s\n",
			    argv[0], strerror(err));
		}
	}

	/* everything is now blank. Wait for the correct password */
	readpw(dpy, &rr, locks, nscreens, hash, &pargs);

	return 0;
}
