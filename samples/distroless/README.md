# Distroless example

This is a basic example using the 'distroless' base image and adding an application. 

The dockerfile also includes busybox from gcr.io/distroless/base:debug - this is only for debug, you should not 
need it for production.

## Test app

The included application is the Istio 'echo' test app, found in istio/pkg/test/echo. This is used in most e2e tests 
in Istio, and will be used to run the e2e tests for CloudRun. 

It will dump request headers and information, and it supports a number of options for testing. 
