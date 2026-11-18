package com.abdulqasim.passwordchecker.strength;

public enum Strength {

    VERY_WEAK("Very weak"),
    WEAK("Weak"),
    FAIR("Fair"),
    STRONG("Strong");

    private final String label;

    Strength(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}