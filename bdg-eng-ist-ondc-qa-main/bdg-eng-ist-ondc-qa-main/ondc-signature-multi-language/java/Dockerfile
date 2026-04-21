FROM maven:3.9-eclipse-temurin-17

WORKDIR /app

# Copy pom.xml first for dependency caching
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source code
COPY src ./src

CMD ["mvn", "test", "-q"]
