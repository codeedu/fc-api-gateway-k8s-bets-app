#!/usr/bin/env bash

docker build -t gcr.io/mvp-mesh-pre-testing/bet .

docker push gcr.io/mvp-mesh-pre-testing/bet:latest