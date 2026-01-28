# SEC-Bench Evaluation Sandbox
# Builds vulnerable code, runs ChiefWiggum + Claude analysis, validates patches

FROM ubuntu:22.04

WORKDIR /secbench

# Install dependencies for building C/C++ projects
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    python3 \
    python3-pip \
    cmake \
    clang \
    llvm \
    sanitizer \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install address/memory sanitizers
RUN apt-get update && apt-get install -y \
    libasan6 \
    libmsan6 \
    libubsan1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY benchmark/requirements.txt /tmp/requirements.txt
RUN pip3 install -q -r /tmp/requirements.txt

# Copy ChiefWiggum
COPY . /secbench/

# Entrypoint: Run evaluation
ENTRYPOINT ["python3", "benchmark/secbench_runner.py"]
CMD ["--dataset", "synthetic", "--limit", "100"]
