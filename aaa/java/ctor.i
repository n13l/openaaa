%pragma(java) jniclasscode=%{
  static {
        try {
                String lib;
                if (System.getProperty("os.name").startsWith("Windows"))
                        lib = "libaaa-0.0.1"; 
                else 
                        lib = "aaa-0.0.1";

                System.loadLibrary(lib);
                System.out.println("native library " + lib + " loaded.");
        } catch (UnsatisfiedLinkError e) {
                System.err.println("native library failed to load." + e);
                System.exit(1);
        }
  }
%}
