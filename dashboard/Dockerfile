FROM node:20-alpine

WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json ./
COPY package-lock.json* ./
RUN npm install

# Copy the rest of the source.
COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]
