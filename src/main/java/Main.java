import massa.its.ITSEntity;

public class Main {
    static public void main(String[] args) {
        try {
            ITSEntity e = new ITSEntity();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }


        System.out.println("Dima is here");
    }
}
