Create a requirements.txt (if any dependencies need to be installed via pip):

# Add any Python dependencies here
# For example:
# requests==2.25.1

Build the Docker container:
Navigate to the directory containing the Dockerfile and run:

    docker build -t digital-forensics .

Run the container:

After building, you can run the container with:

    docker run -v /path/to/your/disk_image:/disk_image digital-forensics

This mounts your disk image to the container and executes the forensics script.
