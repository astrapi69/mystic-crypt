import java.net.*;
public class UrlEq {
  static void cmp(String s) throws Exception {
    URL a = new URL(s);
    URL b = URI.create(s).toURL();
    System.out.println(s);
    System.out.println("  equalStr=" + a.toString().equals(b.toString())
      + " path[" + a.getPath() + "|" + b.getPath() + "]"
      + " query[" + a.getQuery() + "|" + b.getQuery() + "]"
      + " proto[" + a.getProtocol() + "|" + b.getProtocol() + "]"
      + " host[" + a.getHost() + "|" + b.getHost() + "]");
  }
  public static void main(String[] x) throws Exception {
    cmp("https://maps.googleapis.com/maps/api/geocode/json?address=NewYork");
    cmp("http://192.168.178.1/");
    cmp("http://www.abcdefghijkl.de");
    cmp("http://www.a.zz");
  }
}
