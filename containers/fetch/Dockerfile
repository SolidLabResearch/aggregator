# Use a lightweight base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code
COPY app.py .

# Expose port 8080
EXPOSE 8080

# Run the app
CMD ["python", "app.py"]