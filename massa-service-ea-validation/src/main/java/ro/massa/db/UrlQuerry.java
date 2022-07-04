//package ro.massa.db;
//
//public class UrlQuerry {
//
//    private String data = null;
//
//    public UrlQuerry(){
//
//    }
//
//    public UrlQuerry add(String key, String val)
//    {
//        if(data == null)
//        {
//            data = "?";
//        }
//        else
//        {
//            data += "&";
//        }
//
//        data += key + "=" + val;
//        return this;
//    }
//
//    public UrlQuerry add(String key, int val)
//    {
//        return add(key, Integer.toString(val));
//    }
//
//    public String toString()
//    {
//        return data;
//    }
//}
