# Base image
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install PostgreSQL client
RUN apk add --no-cache postgresql-client

# Install dependencies
COPY package*.json ./
RUN npm install

# Bundle app source
COPY . .

# Wait for PostgreSQL script
COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /usr/src/app
USER appuser

# Expose port
EXPOSE 3000

# Command to run the application
CMD ["npm", "run", "dev"] 