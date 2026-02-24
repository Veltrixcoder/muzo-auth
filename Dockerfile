FROM node:20-alpine

# Set working directory
WORKDIR /app

# Install dependencies first (leverage Docker layer cache)
COPY package*.json ./
RUN npm install
RUN npm install multer

# Copy app source
COPY . .

# Expose the port Hugging Face Spaces will provide via $PORT
ENV HOST=0.0.0.0
ENV PORT=7860
EXPOSE 7860

# Start the server; HF Spaces sets PORT env var which our server reads
CMD ["sh", "-c", "PORT=${PORT:-7860} node main.js"]
