package sys.plugable;

class Test implements Notification {
	@Override
	public void event(int device, int type, String info) {
		if (device != Device.HOTPLUG_TYPE_USB)
			return;

		switch (type) {
			case Device.HOTPLUG_EVENT_ARRIVED:
				System.out.println("event arrived");
				break;
			case Device.HOTPLUG_EVENT_LEFT:
				System.out.println("event left");
				break;
		}

		System.out.println("device identifier=" + info);

	}

	public static void main(String[] args) throws Exception {
		HotPlug hotplug = new HotPlug(Device.HOTPLUG_TYPE_USB, "Test");

		while (true) {
			hotplug.event_wait();
			Thread.sleep(1000);

		}
//		hotplug.finalize();
	}
}
