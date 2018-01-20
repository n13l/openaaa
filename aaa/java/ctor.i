%pragma(java) jniclasscode=%{
  static {
        try {
                String lib;
                if (System.getProperty("os.name").startsWith("Windows"))
                        lib = "libaaa"; 
                else 
                        lib = "aaa";

                System.loadLibrary(lib);
                System.out.println("native library " + lib + " loaded.");
        } catch (UnsatisfiedLinkError e) {
                System.err.println("native library failed to load." + e);
                System.exit(1);
        }
  }
%}
