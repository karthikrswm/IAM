# File: README.md (Fragment)

## Running Locally with Docker Compose

This project requires several external services (Database, Cache, Email Catcher, Message Queue) to run. A `docker-compose.yml` file is provided to easily start these services locally.

**Prerequisites:**

* Docker: [Install Docker](https://docs.docker.com/get-docker/)
* Docker Compose: Usually included with Docker Desktop, or install separately.

**Setup:**

1.  **Environment Variables:** Create a file named `.env` in the project root directory (where `docker-compose.yml` is located). Copy the contents from the example below and **replace the placeholder passwords** with secure ones. **Do not commit the `.env` file to version control.**

    ```dotenv
    # .env file
    MYSQL_DATABASE=iam_db
    MYSQL_USER=iam_user
    MYSQL_PASSWORD=iam_password_change_me # Change this!
    MYSQL_ROOT_PASSWORD=root_password_change_me # Change this!
    MYSQL_PORT=3306
    REDIS_PORT=6379
    # REDIS_PASSWORD=your_redis_password # Uncomment if needed
    MAILHOG_SMTP_PORT=1025
    MAILHOG_UI_PORT=8025
    KAFKA_PORT=9092
    ZOOKEEPER_PORT=2181
    ```

2.  **Start Services:** Open a terminal in the project root directory and run:
    ```bash
    docker-compose up -d
    ```
    This will download the necessary images (if not already present) and start the containers in the background (`-d`).

3.  **Check Status:** You can check the status of the containers using:
    ```bash
    docker-compose ps
    ```
    Wait for the health checks (especially for `mysql_db`, `zookeeper`, and `kafka`) to show as `healthy`. This might take a minute or two on the first startup.

4.  **Run Application:** Now you can run the Spring Boot application. It should connect to the services running in Docker using the default configurations provided in `application.properties` (which point to the Docker service names like `mysql_db`, `redis_cache`, `kafka`, `mailhog`).

**Accessing Services:**

* **MySQL:** Connect using a client on `localhost:3306` (or the `MYSQL_PORT` you set) with the user/password from your `.env` file.
* **Redis:** Connect using a client on `localhost:6379` (or the `REDIS_PORT`).
* **MailHog:** Access the web UI in your browser at `http://localhost:8025` (or the `MAILHOG_UI_PORT`). Emails sent by the application will appear here.
* **Kafka:** The broker is accessible to the application via `kafka:9092` (internal Docker network) and from your host machine via `localhost:9092` (or the `KAFKA_PORT`).

**Stopping Services:**

To stop the containers, run:
```bash
docker-compose down