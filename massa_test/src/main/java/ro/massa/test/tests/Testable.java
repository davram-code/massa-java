package ro.massa.test.tests;

import ro.massa.test.CryptoClientOps;

abstract class Testable {
    String name;
    CryptoClientOps ccOps;

    void init() {
        System.out.println("Initiating test on: " + name);
    }
    void cleanup() {
        System.out.println("Cleanup: " + name);
    }
    abstract void run();

    Testable(String name, CryptoClientOps ccOps) {
        this.name = name;
        this.ccOps = ccOps;
    }

    public void measure() {
        init();


        long startTime = System.nanoTime();
        run();
        long stopTime = System.nanoTime();
        long executionTime = stopTime - startTime;

        if (verify()) {
            System.out.println("Test PASSED!");
        } else {
            System.out.println("Test FAILED!");
        }

        System.out.println("Function " + this.name + " executed in 0." + executionTime + " seconds");
        cleanup();
    }

    public boolean verify() { return true; }
}