FROM ruby:3.2-alpine

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache build-base libsodium-dev

# Copy Gemfile
COPY Gemfile* ./

# Install Ruby gems
RUN bundle install

# Copy application code
COPY . .

CMD ["ruby", "test_signature.rb"]
