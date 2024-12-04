# Step 1: Select the base image
FROM python:3.10-slim

# Step 2: Copy the files
WORKDIR /app
COPY . /app

# Step 3: Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 4: Install Redis
RUN apt-get update && apt-get install -y redis-server && apt-get clean

# Step 5: Expose ports (if external Redis is required)
EXPOSE 6379

# Step 6: Run the application
CMD ["python", "src/main.py"]
