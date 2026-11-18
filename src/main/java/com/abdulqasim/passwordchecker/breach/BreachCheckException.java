package com.abdulqasim.passwordchecker.breach;

// BreachCheckException
// What: Reports the error when the breach check cannot be completed;
// for example, a lack of internet connection could cause an exception to be thrown.

// Why: A clear error type lets the rest of the program tell the user the check couldn't be completed for whatever reason,
// rather than giving false security by saying the password was found when no detections are caught.

 public class BreachCheckException extends RuntimeException {
    
    public BreachCheckException(String msg) {
        super(msg);
    }

    public BreachCheckException (String msg, Throwable cause) {
        super(msg, cause);
    }
}
