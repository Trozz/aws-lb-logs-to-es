# AWS LoadBalancer logs to ElasticSearch
This repository contains a serverless application that reads from S3 and write to a ElasticSearch cluster

## ElasticSearch versions
Simply change the version numbers in `requirements.txt` to support other versions of ElasticSearch

## Variables
 - s3bucket
 - es_nodes
 - index_prefix

## TODO
 - Allow Encryption
 - Allow authentication
