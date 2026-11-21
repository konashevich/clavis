package clavis.holder;

public final class Core {
    static {
        System.loadLibrary("clavis_ffi");
    }

    private Core() {}

    public static native int profile(byte[] buffer);
}
