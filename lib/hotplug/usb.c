

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/stack.h>

#include <dlfcn.h>

#include <hotplug/lib.h>
#include <hotplug/prv.h>

/* API_VERSION >= 0x01000102 */
#undef  __call
#ifdef WIN32
#define __call __stdcall
#else
#define __call
#endif

#define DLMODE (RTLD_NOW | RTLD_GLOBAL)

#define USB_DEVICE_ARRIVED    0x01
#define USB_DEVICE_LEFT       0x02
#define USB_MATCH_ANY        -1
#define USB_HOTPLUG_ENUMERATE 1

struct usb;
struct dev;
struct cb;
struct fn;

struct ver {
	const u16 major;
	const u16 minor;
	const u16 micro;
	const u16 nano;
	const char *rc;
	const char *desc;
};

enum usb_log_level {                                                         
	USB_LOG_LEVEL_NONE = 0,                                              
	USB_LOG_LEVEL_ERROR,                                                 
	USB_LOG_LEVEL_WARNING,                                               
	USB_LOG_LEVEL_INFO,                                                  
	USB_LOG_LEVEL_DEBUG,                                                 
};

enum usb_capability {
	CAP_HAS_CAPABILITY = 0,
	CAP_HAS_HOTPLUG, 	
	CAP_HAS_HID_ACCESS, 	
	CAP_SUPPORTS_DETACH_KERNEL_DRIVER, 
};

enum usb_class_code {
	USB_CLASS_PER_INTERFACE = 0,
	/** Audio class */
	USB_CLASS_AUDIO = 1,
	/** Communications class */
	USB_CLASS_COMM = 2,
	/** Human Interface Device class */
	USB_CLASS_HID = 3,
	/** Physical */
	USB_CLASS_PHYSICAL = 5,
	/** Printer class */
	USB_CLASS_PRINTER = 7,
	/** Image class */
	USB_CLASS_PTP = 6, /* legacy name from USB-0.1 usb.h */
	USB_CLASS_IMAGE = 6,
	/** Mass storage class */
	USB_CLASS_MASS_STORAGE = 8,
	/** Hub class */
	USB_CLASS_HUB = 9,
	/** Data class */
	USB_CLASS_DATA = 10,
	/** Smart Card */
	USB_CLASS_SMART_CARD = 0x0b,
	/** Content Security */
	USB_CLASS_CONTENT_SECURITY = 0x0d,
	/** Video */
	USB_CLASS_VIDEO = 0x0e,
	/** Personal Healthcare */
	USB_CLASS_PERSONAL_HEALTHCARE = 0x0f,
	/** Diagnostic Device */
	USB_CLASS_DIAGNOSTIC_DEVICE = 0xdc,
	/** Wireless class */
	USB_CLASS_WIRELESS = 0xe0,
	/** Application class */
	USB_CLASS_APPLICATION = 0xfe,
	/** Class is vendor-specific */
	USB_CLASS_VENDOR_SPEC = 0xff
};


typedef int  (__call *usb_call)(struct usb *, struct dev *,int event, void *);

int __call
__usb_call(struct usb *usb, struct dev *dev, int event, void *usr)
{
	sys_dbg("event=%d", event);
	fflush(stdout);
	return 0;
}

                                                                                
int  (__call *usb_init)(struct usb **usb);
void (__call *usb_exit)(struct usb *usb);
void (__call *usb_set_debug)(struct usb *, int level);
const char * (__call *usb_error_name)(int code);
int  (__call *usb_has_capability)(uint32_t capability);
int  (__call *usb_register)(struct usb *, int , int , int, int, int,
              usb_call, void *, int *);
void (__call *usb_deregister)(struct usb *,struct cb *);

int (__call *usb_handle_events)(struct usb *);
int (__call *usb_handle_events_completed)(struct usb *, int *completed);

struct ver* (__call *usb_get_version)(void);

struct plugable_usb {
	void       *dl;
	struct usb *ctx;
	int         rv;
	int         id;
};

static void
link_usb(struct plugable_usb *usb)
{
	void *dl = usb->dl;
        usb_get_version    = dlsym(dl, "libusb_get_version");
	usb_has_capability = dlsym(dl, "libusb_has_capability");
	usb_error_name     = dlsym(dl, "libusb_error_name");
        usb_init           = dlsym(dl, "libusb_init");
        usb_exit           = dlsym(dl, "libusb_exit");
        usb_set_debug      = dlsym(dl, "libusb_set_debug");
        usb_register       = dlsym(dl, "libusb_hotplug_register_callback");
        usb_deregister     = dlsym(dl, "libusb_hotplug_deregister_callback");
	usb_handle_events_completed = dlsym(dl, "libusb_handle_events_completed");
	usb_handle_events  = dlsym(dl, "libusb_handle_events");
}

int
plugable_usb_init(struct hotplug *hot)
{
	struct plugable_usb *usb = mp_alloc_zero(hot->mp, sizeof(*usb));
	const char *name = "libusb-1.0." SHLIB_EX;
	sys_dbg("loading usb support library name=%s", name);
	if (!(usb->dl = dlopen(name, DLMODE))) {
		sys_err("loading library failed");
		return -EINVAL;
	}

	link_usb(usb);

	if (!usb_get_version)
		return -EINVAL;

	usb_init(&usb->ctx);
	usb_set_debug(usb->ctx, USB_LOG_LEVEL_DEBUG);

        struct ver* ver = usb_get_version();
        sys_dbg("library version %d.%d.%d%s (%s)",
	        ver->major, ver->minor, ver->micro, ver->rc, ver->desc);	

	sys_dbg("CAP_HAS_HOTPLUG=%d",
	        usb_has_capability(CAP_HAS_HOTPLUG));
	sys_dbg("CAP_HAS_HID_ACCESS=%d",
	        usb_has_capability(CAP_HAS_HID_ACCESS));

	int event = USB_DEVICE_ARRIVED | USB_DEVICE_LEFT;
	usb->rv = usb_register(usb->ctx, event, USB_HOTPLUG_ENUMERATE, 
	             USB_MATCH_ANY, USB_MATCH_ANY, USB_MATCH_ANY, 
		     __usb_call, hot, &usb->id);

	sys_dbg("register: %d %d", usb->rv, usb->id);
	sys_dbg("%s", usb_error_name(usb->rv));

	hot->usb = usb;
	fflush(stdout);
	return 0;
}

int
plugable_usb_wait(struct hotplug *hotplug)
{
	struct plugable_usb *usb = hotplug->usb;
	return usb_handle_events(usb->ctx);
}

int
plugable_usb_fini(struct hotplug *hotplug)
{
	struct plugable_usb *usb = hotplug->usb;
//	usb_exit(usb->ctx);
	dlclose(usb->dl);
	return 0;
}
