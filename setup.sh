#!/bin/bash
sls plugin install --name serverless-python-requirements
npm install serverless-plugin-existing-s3
sls deploy
sls s3deploy
