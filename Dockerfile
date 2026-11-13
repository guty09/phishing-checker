# Builds the React app and the Spring Boot API into one image.
# Hosted builds use ./mvnw. Local Windows builds use backend/mvn.ps1 so files stay on D:.

FROM node:24-bookworm AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /src
COPY backend/ ./backend/
COPY --from=frontend /src/frontend/dist ./backend/src/main/resources/static
WORKDIR /src/backend
RUN sed -i 's/\r$//' mvnw && chmod +x mvnw && ./mvnw -B -DskipTests package

FROM eclipse-temurin:21-jre-jammy
RUN groupadd --system --gid 65532 app && useradd --system --uid 65532 --gid 65532 --no-create-home app
WORKDIR /app
COPY --from=build /src/backend/target/phishing-checker-0.0.1-SNAPSHOT.jar /app/app.jar
EXPOSE 8081
USER app
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
