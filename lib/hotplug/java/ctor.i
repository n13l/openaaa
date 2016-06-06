%pragma(java) jniclasscode=%{
  static {
        try {
                String lib;
                if (System.getProperty("os.name").startsWith("Windows"))
                        lib = "libhotplug-0.0.1-beta"; 
                else 
                        lib = "hotplug-0.0.1-beta";

                System.loadLibrary(lib);
                System.out.println("native library " + lib + " loaded.");
        } catch (UnsatisfiedLinkError e) {
                System.err.println("native library failed to load." + e);
                System.exit(1);
        }
  }
%}
