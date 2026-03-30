FROM gradle:9-jdk21-alpine AS build
WORKDIR /app
COPY . .
RUN gradle bootJar --no-daemon

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/build/libs/*.jar authservice.jar
ENTRYPOINT ["java", "-jar", "authservice.jar"]