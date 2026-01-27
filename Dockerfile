FROM rust:1.93.0-alpine3.21 AS builder

WORKDIR /app

# Copy manifest and source files
COPY . .

# Build the application
RUN cargo build --release

FROM alpine:3.21 AS runtime

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/nox-kms .

# Run the application
ENTRYPOINT ["/app/nox-kms"]
