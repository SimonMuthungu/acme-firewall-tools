# Use a lightweight Python base image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install pytest ruff

# Copy all the project files into the container
COPY . .

# Run tests during the build process
RUN pytest -v

# The default command when the container starts
CMD ["python", "rule_audit.py"]