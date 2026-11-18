package com.abdulqasim.passwordchecker.strength;

import java.util.List;
import java.util.Objects;

public record StrengthResult(Strength strength, List<String> feedback) {

    public StrengthResult {
        Objects.requireNonNull(strength, "strength must not be null");
        feedback = List.copyOf(feedback);
    }
}