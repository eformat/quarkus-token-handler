Instructions
============

## Usage

To start up the image

    podman run -it -p 8080:8080 -p 8443:8443 thales-auth

## Building the image

    cp ~/Donwloads/'Keycloak Luna Patch.zip' patch/ # this is from thales support
    ./patch_luna.sh
    podman build -t=thales-auth .

## How to customize the image

The following environment variables control configuration of the app:

    KEYCLOAK_USER=admin
    KEYCLOAK_PASSWORD=password
