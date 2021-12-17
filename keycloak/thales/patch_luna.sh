#!/bin/bash

cd patch

if [ ! -f 'Keycloak Luna Patch.zip' ]; then echo "Copy 'Keycloak Luna Patch.zip' to the patch folder." && exit 1; fi

unzip 'Keycloak Luna Patch.zip'
tar xf '630-000513-001_SW_Patch_keycloak_UC_Clnt_10.3.0_Custom_Release.tar'
unzip '630-000513-001_SW_Patch_keycloak_UC_Clnt_10.3.0_Custom_Release/keycloak-spi-luna-keystore-1.0-assemblyModule.zip'