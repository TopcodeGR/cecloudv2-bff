# ---- Stage 1: Build & Test ----
FROM eclipse-temurin:17-jdk-alpine AS build

WORKDIR /app

# Copy only necessary files to optimize layer caching
COPY pom.xml mvnw ./
COPY .mvn .mvn

# Copy the Maven settings.xml for private repo authentication
COPY maven-settings.xml /root/.m2/settings.xml

# Build arguments for authentication
ARG REPOSILITE_USERNAME
ARG REPOSILITE_PASSWORD

# Set environment variables for Maven
ENV REPOSILITE_USERNAME=${REPOSILITE_USERNAME}
ENV REPOSILITE_PASSWORD=${REPOSILITE_PASSWORD}


COPY src src

# If tests pass, proceed with packaging
RUN chmod +x ./mvnw
RUN ./mvnw clean package

# ---- Stage 2: Create the final image ----
FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

# Copy only the built JAR
COPY --from=build /app/target/*.jar bff.jar

EXPOSE 7081

ENTRYPOINT ["java", "-jar", "bff.jar"]
