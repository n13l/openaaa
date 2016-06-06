#include <sys/compiler.h>
#include <sys/cpu.h>
#include <mem/pool.h>
#include <stdlib.h>
#include <stdio.h>
#include <hotplug/prv.h>
#include <hotplug/lib.h>

struct hotplug *
hotplug_init(void)
{
	struct mempool *mp = mp_new(CPU_PAGE_SIZE);
	struct hotplug *hp = mp_alloc_zero(mp, sizeof(*hp));

	hp->mp = mp;

	sys_dbg("hotplug init");

	plugable_usb_init(hp);
	return hp;
}

int                                                                             
hotplug_wait(struct hotplug *hp)
{
	return plugable_usb_wait(hp);
}

void
hotplug_fini(struct hotplug *hp)
{
	sys_dbg("hotplug fini");
	plugable_usb_fini(hp);
	mp_delete(hp->mp);
}
