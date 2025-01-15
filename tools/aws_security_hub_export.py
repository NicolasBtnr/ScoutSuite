#!/usr/bin/env python3

from ScoutSuite.providers.aws.utils import get_caller_identity
from ScoutSuite.core.console import set_logger_configuration, print_info, print_exception
from tools.utils import results_file_to_dict

import datetime
import argparse
import boto3
import json

def replace_strings(data, replacement_dict):
    if isinstance(data, str):
        # Replace any substrings matching dictionary keys with their values
        for key, value in replacement_dict.items():
            data = data.replace(key, value)
        return data
    elif isinstance(data, list):
        # Recursively process each element in the list
        return [replace_strings(item, replacement_dict) for item in data]
    elif isinstance(data, dict):
        # Recursively process each value in the dictionary
        return {k: replace_strings(v, replacement_dict) for k, v in data.items()}
    else:
        # Return data unchanged if it's not a string, list, or dictionary
        return data

def find_scoutid_names(data,scoutid_name_map):
    if isinstance(data, dict):
        for key, value in data.items():
            if key.startswith("scoutid-") and isinstance(value, dict) and 'name' in value:
                scoutid_name_map[key] = value['name']
            else:
                find_scoutid_names(value, scoutid_name_map)
    elif isinstance(data, list):
        for item in data:
            find_scoutid_names(item, scoutid_name_map)

def upload_findigs_to_securityhub(session, formatted_findings_list):
    try:
        if formatted_findings_list:
            print_info('Batch uploading {} findings'.format(len(formatted_findings_list)))
            securityhub = session.client('securityhub')
            response = securityhub.batch_import_findings(Findings=formatted_findings_list)
            print_info('Upload completed, {} succeeded, {} failed'.format(response.get('SuccessCount'),
                                                                          response.get('FailedCount')))
            return response
    except Exception as e:
        print_exception(f'Unable to upload findings to Security Hub: {e}')


def format_finding_to_securityhub_format(aws_account_id,
                                         region,
                                         creation_date,
                                         finding_key,
                                         finding_value,scoutid_name_map):
    try:

        if finding_value.get('level') == 'danger':
            label = 'HIGH'
        elif finding_value.get('level') == 'warning':
            label = 'MEDIUM'
        else:
            label = 'INFORMATIONAL'

        format_time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

        resource_id = replace_strings(finding_value.get('items'),scoutid_name_map)
        if isinstance(resource_id, list):
            resources = [
                {
                    'Type': 'undefined',
                    'Id': str(res),  # Ensure each resource ID is a string
                    'Partition': 'aws',
                    'Region': region
                }
                for res in resource_id[:32]
            ]
        else:
            resources = [
                {
                    'Type': 'undefined',
                    'Id': str(resource_id),  # Ensure resource_id is a string
                    'Partition': 'aws',
                    'Region': region
                }
            ]

        formatted_finding = {
            'SchemaVersion': '2018-10-08',
            'Id': finding_key,
            'ProductArn':
                'arn:aws:securityhub:' + region + ':' + aws_account_id + ':product/' + aws_account_id + '/default',
            'GeneratorId': f'scoutsuite-{aws_account_id}',
            'AwsAccountId': aws_account_id,
            'Types': ['Software and Configuration Checks/AWS Security Best Practices'],
            'FirstObservedAt': creation_date,
            'CreatedAt': format_time,
            'UpdatedAt': format_time,
            'Severity': {
                'Label': label
            },
            'Title': finding_value.get('description'),
            'Description': finding_value.get('rationale') if finding_value.get('rationale') else 'None',
            'Remediation': {
                'Recommendation': {
                    'Text': finding_value.get('remediation', 'None') if finding_value.get('remediation') else 'None'
                }
            },
            'ProductFields': {'Product Name': 'Scout Suite'},
            'Resources': resources,
            'Compliance': {
                'Status': 'FAILED'
            },
            'RecordState': 'ACTIVE'
        }
        return formatted_finding
    except Exception as e:
        print_exception(f'Unable to process finding: {e}')


def process_results_file(f,
                         region,scoutid_name_map):
    try:
        formatted_findings_list = []
        results = results_file_to_dict(f)

        aws_account_id = results["account_id"]
        creation_date = datetime.datetime.strptime(results["last_run"]["time"], '%Y-%m-%d %H:%M:%S%z').isoformat()

        for service in results.get('service_list'):
            for finding_key, finding_value in results.get('services', {}).get(service).get('findings').items():
                if finding_value.get('items'):
                    formatted_finding = format_finding_to_securityhub_format(aws_account_id,
                                                                             region,
                                                                             creation_date,
                                                                             finding_key,
                                                                             finding_value,
                                                                             scoutid_name_map)
                    formatted_findings_list.append(formatted_finding)

        return formatted_findings_list
    except Exception as e:
        print_exception(f'Unable to process results file: {e}')


def run(file):
    session = boto3.Session()
    # Test querying for current user
    get_caller_identity(session)
    print_info(f'Authenticated with the provided environment credentials')
     
    try:
        with open(file) as f:
            data = json.loads(f.read().split('=', 1)[1].strip())
            # Dictionary to store the associations
            scoutid_name_map = {}
            find_scoutid_names(data,scoutid_name_map)
            f.seek(0)
            formatted_findings_list = process_results_file(f,
                                                           session.region_name,scoutid_name_map)
    except Exception as e:
        print_exception(f'Error during processing {file}: {e}')

    #print_info(f'List of findings : {formatted_findings_list}')
    upload_findigs_to_securityhub(session, formatted_findings_list)


if __name__ == "__main__":

    # Configure the debug level
    set_logger_configuration()

    parser = argparse.ArgumentParser(description='Tool to upload a JSON report to AWS Security Hub')
    parser.add_argument('-f', '--file',
                        required=True,
                        help="The path of the JSON results file to process, e.g. "
                             "\"scoutsuite-report/scoutsuite-results/scoutsuite_results_aws-<profile>.js\".")
    args = parser.parse_args()

    try:
        run(args.file)
    except Exception as e:
        print_exception(f'Unable to complete: {e}')
