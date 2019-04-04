import boto3
import json
import gzip
import tempfile
from elasticsearch import Elasticsearch
import os
import datetime
import logging
import re
import errno
from botocore.client import Config


config = Config(connect_timeout=5, retries={'max_attempts': 0})
logger = logging.getLogger('lambda')
logger.setLevel(logging.INFO)
environ = os.environ
es_nodes_list = environ['es_nodes'].split(",")
es_nodes = []
for n in es_nodes_list:
    es_nodes.append(
        {
            'host': n.split(":")[0],
            'port': n.split(":")[1]
        }
    )

es = Elasticsearch(
    es_nodes,
    sniff_on_start=True,
    sniff_on_connection_fail=True,
    sniffer_timeout=10

)
now = datetime.datetime.now()
index_suffix = now.strftime("%Y-%m-%d")
index_prefix = environ['index_prefix']
index_name = "{}-{}".format(index_prefix, index_suffix)


def entry_handler(event, context):
    """
    Handle the start of the lambda
    Identify if it is ALB or ELB
    """
    key = event['Records'][0]['s3']['object']['key']
    logger.info("Begining run for object {}".format(key))
    if key.endswith('.gz') or key.endswith('.log'):
        regex_handler(event)
    else:
        logger.debug("key is not gz or log, raise error and exit")
        logger.error("Error: unknown extension")
        raise SystemExit(1)


def getS3File(bucket, key):
    """
    This function gets the object from S3,
    stores it in a temp location on disk,
    opens the file using gzip as text and passes the object
    """
    logger.debug("getS3File started")
    s3 = boto3.resource('s3', config=config)
    temp_file_path = "{}/{}".format(tempfile.gettempdir(), key)
    split_list = temp_file_path.split('/')
    split_list.pop()
    temp_file_dir = "/".join(split_list)
    try:
        os.makedirs(temp_file_dir)
    except OSError:
        logger.warn("Failed to create directory {}".format(temp_file_dir))
    # This downloads as an object
    with open(temp_file_path, 'wb') as data:
        s3.Bucket(bucket).download_fileobj(key, data)
    if key.endswith('.gz'):
        temp_file = gzip.open(temp_file_path, 'rt')
    else:
        temp_file = open(temp_file_path, 'rt')
    return temp_file


def regex_handler(event):
    key = event['Records'][0]['s3']['object']['key']
    bucket = event['Records'][0]['s3']['bucket']['name']
    obj = getS3File(bucket, key)
    lines = obj.readlines()
    events = []
    if key.endswith('.gz'):
        regex_list = [
            '(?P<type>[^ ]*)',
            '(?P<time>[^ ]*)',
            '(?P<elb>[^ ]*)',
            '(?P<client_ip>[^ ]*):(?P<client_port>[0-9]*)',
            '(?P<target_ip>[^ ]*)[:-](?P<target_port>[0-9]*)',
            '(?P<request_processing_time>[-.0-9]*)',
            '(?P<target_processing_time>[-.0-9]*)',
            '(?P<response_processing_time>[-.0-9]*)',
            '(?P<elb_status_code>|[-0-9]*)',
            '(?P<target_status_code>-|[-0-9]*)',
            '(?P<received_bytes>[-0-9]*)',
            '(?P<sent_bytes>[-0-9]*) \"(?P<request_verb>[^ ]*)',
            '(?P<request_url>[^ ]*)',
            '(?P<request_proto>- |[^ ]*)\"',
            '\"(?P<user_agent>[^\"]*)\"',
            '(?P<ssl_cipher>[A-Z0-9-]+)',
            '(?P<ssl_protocol>[A-Za-z0-9.-]*)',
            '(?P<target_group_arn>[^ ]*) \"(?P<trace_id>[^\"]*)\"',
            '\"(?P<domain_name>[^\"]*)\" \"(?P<chosen_cert_arn>[^\"]*)\"',
            '(?P<matched_rule_priority>[-.0-9]*)',
            '(?P<request_creation_time>[^ ]*)',
            '\"(?P<actions_executed>[^\"]*)\"',
            '\"(?P<redirect_url>[^\"]*)\"(?P<lambda_error_reason>$|',
            '\"[^ ]*\")(?P<new_field>.*)']
        regex = " ".join(regex_list)
        for line in lines:
            logger.debug("GZIP In loop with line")
            meta_obj = {"index": {"_index": index_name, "_type": "aws_alb"}}
            events.append(json.dumps(meta_obj))
            events.append(json.dumps(re.match(regex, line).groupdict()))
        sendToelasticsearch('aws_alb', events)
    elif key.endswith('.log'):
        regex_list = [
            '(?P<time>[^ ]*)',
            '(?P<elb>[^ ]*)',
            '(?P<client_ip>[^ ]*):(?P<client_port>[0-9]*)',
            '(?P<target_ip>[^ ]*)[:-](?P<target_port>[0-9]*)',
            '(?P<request_processing_time>[-.0-9]*)',
            '(?P<backend_processing_time>[-.0-9]*)',
            '(?P<client_response_time>[-.0-9]*)',
            '(?P<elb_status_code>|[-0-9]*)',
            '(?P<target_status_code>-|[-0-9]*)',
            '(?P<received_bytes>[-0-9]*)',
            '(?P<sent_bytes>[-0-9]*) \\\"(?P<request_verb>[^ ]*)',
            '(?P<request_url>[^ ]*)',
            '(?P<request_proto>- |[^ ]*)\\\" (?P<user_agent>\"[^\"]*\")',
            '(?P<ssl_cipher>[A-Z0-9-]+)',
            '(?P<ssl_protocol>[A-Za-z0-9.-]*)$']
        regex = " ".join(regex_list)
        for line in lines:
            logger.debug("OPEN In loop with line")
            meta_obj = {"index": {"_index": index_name, "_type": "aws_elb"}}
            events.append(json.dumps(meta_obj))
            events.append(json.dumps(re.match(regex, line).groupdict()))
        sendToelasticsearch('aws_elb', events)
    obj.close()
    return True


def sendToelasticsearch(doc_type, json_list):
    if len(json_list) == 1:
        single_ES(doc_type, json_list[0])
    else:
        multi_ES(doc_type, json_list)


def single_ES(doc_type, json_list):
    logger.debug("Single")
    """ This should NEVER run """
    try:
        logger.debug("Sending to ElasticSearch")
        res = es.index(
            index=index_name,
            doc_type=doc_type,
            body=json_list)
        if not res['created']:
            logger.error("ElasticSearch entry failed."
                         "json content: {}".format(json.dumps(json_list)))
        return True
    except Exception as e:
        logger.error(json_list)
        logger.error(e)
        raise SystemExit(1)


def multi_ES(doc_type, json_list):
    logger.debug("Multi")
    body_data = "\n".join(json_list)
    try:
        logger.debug("Sending to ElasticSearch")
        res = es.bulk(
            index=index_name,
            doc_type=doc_type,
            body=body_data)
        if res['errors']:
            logger.error("ElasticSearch entry failed."
                         "json content: {}".format(json.dumps(json_list)))
        logger.info("Data inserted")
        return True
    except Exception as e:
        logger.error(json_list)
        logger.debug(body_data)
        logger.error(e)
        raise SystemExit(1)
