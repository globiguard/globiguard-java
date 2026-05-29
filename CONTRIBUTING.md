# Contributing

GlobiGuard Java SDK changes should keep runtime dependencies at zero unless a security review accepts a specific exception.

## Validate locally

```bash
javac -d target/classes src/main/java/com/globiguard/Globiguard.java
javac -cp target/classes -d target/test-classes src/test/java/com/globiguard/GlobiguardTest.java
java -cp target/classes;target/test-classes com.globiguard.GlobiguardTest
```

If Maven is installed, also run `mvn test package`.

