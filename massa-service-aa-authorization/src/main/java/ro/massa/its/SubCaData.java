package ro.massa.its;

public class SubCaData {
    public String getName() {
        return name;
    }

    public int getValidityYears() {
        return validityYears;
    }

    private String name;
    private int validityYears;

    public SubCaData(String name, int validityYears)
    {
        this.name = name;
        this.validityYears = validityYears;
    }


}
