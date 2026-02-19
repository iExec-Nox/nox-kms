FROM rust:1.93.0-alpine3.23 AS builder

# Install build dependencies
RUN apk add --no-cache openssl-dev=3.5.5-r0 openssl-libs-static=3.5.5-r0

WORKDIR /app

# Copy manifest and source files
COPY . .

# Build the application
RUN cargo build --release

FROM scratch AS runtime

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/nox-kms .

# Run the application
ENTRYPOINT ["/app/nox-kms"]
