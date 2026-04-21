FROM php:8.2-cli

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libsodium-dev \
    git \
    unzip \
    && docker-php-ext-install sodium

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Copy composer files
COPY composer.json ./

# Install PHP dependencies
RUN composer install --no-interaction

# Copy application code
COPY . .

CMD ["php", "test_signature.php"]
